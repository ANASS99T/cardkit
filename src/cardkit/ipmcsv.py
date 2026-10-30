"""
Lossless Mastercard |reg| IPM <-> CSV conversion.

Converting an IPM file to CSV and back gives a file that is byte-for-byte identical to the original.
Nothing is converted, trimmed or masked:

* text fields are written exactly as they appear in the file (spaces and leading zeros kept)
* binary fields (DE55 ICC data) are written as hex, exactly as in the file
* PDS fields (DE48, DE62, DE123-125) are kept as the raw DE value
* records that can't be parsed are kept whole in the ``RAW`` column (as hex)
* file level details (encoding, 1014 blocking, end of file marker, trailing bytes) are kept in a
  ``META`` row

Read and write CSV files::

    from cardkit import ipmcsv
    ipmcsv.convert_ipm_to_csv('in.ipm', 'out.csv')   # verifies the CSV rebuilds the exact file
    ipmcsv.convert_csv_to_ipm('out.csv', 'new.ipm')

CSV layout
----------

=========  ==================================================================================
Column     Content
=========  ==================================================================================
ROW        ``META`` for the file details row, otherwise the record number
MTI        message type indicator
BITMAP     the record bitmap as hex. A bit that is set marks the field as present, even when
           the cell is empty (a present but empty LLVAR field)
DEn        the field value (only columns for fields used in the file are written)
RAW        hex of the full record when it could not be parsed. Used as-is when rebuilding.
           In the META row it holds the file details.
=========  ==================================================================================

A text value that can't be shown safely in CSV (control characters, or a value starting with
``hex:``) is written as ``hex:`` followed by the hex of its bytes.

When a CSV without file header (MTI 1644, DE24 697) or trailer (MTI 1644, DE24 695) records is
converted to IPM, they are generated. A CSV made from an IPM file that had no header or trailer
remembers that in its META row, so no header or trailer is added to it.
"""
import csv
import datetime
import functools
import hashlib
import io
import logging
import os
import typing
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field

from cardkit import CardutilError
from cardkit.config import config as default_config

LOGGER = logging.getLogger(__name__)

DEFAULT_ENCODING = 'cp037'  # used unless an encoding is given
HEX_PREFIX = 'hex:'
BLOCK_DATA_SIZE = 1012
BLOCK_SIZE = 1014
BLOCK_TRAILER = b'\x40\x40'
META_ROW = 'META'
META_VERSION = '1'
HEADER_FUNCTION_CODE = '697'
TRAILER_FUNCTION_CODE = '695'
FILE_CONTROL_MTI = '1644'
PARALLEL_MIN_RECORDS = 20000  # files with fewer records are converted in a single process


class IpmCsvError(CardutilError):
    pass


@functools.lru_cache(maxsize=None)
def _safe_bytes(encoding: str) -> bytes:
    """
    Bytes that decode to a single printable character (or space) and encode back to the same byte.
    A value is CSV safe when ``value.translate(None, _safe_bytes(encoding))`` is empty.
    """
    safe = []
    for byte in range(256):
        try:
            char = bytes([byte]).decode(encoding)
        except UnicodeError:
            continue
        if len(char) == 1 and (char == ' ' or char.isprintable()) and char.encode(encoding) == bytes([byte]):
            safe.append(byte)
    return bytes(safe)


@functools.lru_cache(maxsize=None)
def _to_ascii_digits(encoding: str) -> bytes:
    """
    Translation table mapping the encoding's digit bytes to ASCII digits and every other byte to
    ``x``, so a length prefix is valid only if it is exactly the encoding's digits.
    """
    table = bytearray(b'x' * 256)
    for digit, byte in zip(b'0123456789', '0123456789'.encode(encoding)):
        table[byte] = digit
    return bytes(table)


@dataclass(frozen=True)
class FieldSpec:
    bit: int
    length_size: int   # 0 for FIXED, 2 for LLVAR, 3 for LLLVAR
    length: int        # fixed length (FIXED fields only)
    binary: bool       # shown as hex in CSV


def get_field_specs(bit_config: dict = None) -> typing.Dict[int, FieldSpec]:
    """
    Build field specs from a cardutil style ``bit_config`` dict.

    Fields with ``field_processor`` ICC, or ``field_binary`` true, are binary.
    """
    if bit_config is None:
        bit_config = default_config['bit_config']
    specs = {}
    for key, bit_def in bit_config.items():
        bit = int(key)
        if bit == 1:
            continue
        field_type = bit_def.get('field_type', 'FIXED')
        length_size = {'FIXED': 0, 'LLVAR': 2, 'LLLVAR': 3}.get(field_type)
        if length_size is None:
            raise IpmCsvError(f'DE{bit}: unsupported field_type {field_type}')
        binary = bit_def.get('field_binary', bit_def.get('field_processor') == 'ICC')
        specs[bit] = FieldSpec(bit, length_size, bit_def.get('field_length', 0), bool(binary))
    return specs


@dataclass
class IpmRecord:
    """
    One IPM record.

    Parsed records have ``mti``, ``bitmap`` and ``fields`` (raw field bytes keyed by bit, without
    length prefix). Records that could not be parsed only have ``raw``.
    """
    mti: bytes = b''
    bitmap: bytes = b''
    fields: typing.Dict[int, bytes] = field(default_factory=dict)
    raw: typing.Optional[bytes] = None

    def text(self, bit: int, encoding: str) -> typing.Optional[str]:
        value = self.fields.get(bit)
        return None if value is None else value.decode(encoding)

    def is_file_control(self, encoding: str, function_code: str) -> bool:
        if self.raw is not None:
            return False
        return self.mti.decode(encoding) == FILE_CONTROL_MTI and self.text(24, encoding) == function_code


@dataclass
class IpmFile:
    """
    In memory image of an IPM file holding everything needed to rebuild it exactly.
    """
    records: typing.List[IpmRecord] = field(default_factory=list)
    encoding: str = DEFAULT_ENCODING
    blocked: bool = False
    terminator: bool = True                    # zero length record at end of VBS data
    tail: bytes = b''                          # bytes after the terminator (incl. 1014 fill)
    block_trailer: bytes = BLOCK_TRAILER       # 2 bytes ending each 1014 block
    block_trailers: typing.Dict[int, bytes] = field(default_factory=dict)  # blocks ending differently
    had_header: bool = True
    had_trailer: bool = True

    @property
    def has_header(self) -> bool:
        return bool(self.records) and self.records[0].is_file_control(self.encoding, HEADER_FUNCTION_CODE)

    @property
    def has_trailer(self) -> bool:
        return bool(self.records) and self.records[-1].is_file_control(self.encoding, TRAILER_FUNCTION_CODE)


# --------------------------------------------------------------------------------------------
# record level
# --------------------------------------------------------------------------------------------

def _is_ascii_digits(text: str) -> bool:
    return bool(text) and all('0' <= ch <= '9' for ch in text)


def parse_record(record: bytes, specs: typing.Dict[int, FieldSpec], encoding: str) -> IpmRecord:
    """
    Parse an ISO8583 record into raw field bytes. Raises :class:`IpmCsvError` when not parseable.
    """
    if len(record) < 12:
        raise IpmCsvError('record too short for MTI and bitmap')
    bitmap_size = 16 if record[4] & 0x80 else 8
    bitmap = record[4:4 + bitmap_size]
    if len(bitmap) != bitmap_size:
        raise IpmCsvError('record too short for secondary bitmap')
    bit_count = bitmap_size * 8
    remaining = int.from_bytes(bitmap, 'big') & ~(1 << (bit_count - 1))  # bit 1 is not a field
    digits = _to_ascii_digits(encoding)
    pos = 4 + bitmap_size
    fields = {}
    while remaining:  # highest set bit first = lowest field number first
        top = remaining.bit_length()
        remaining ^= 1 << (top - 1)
        bit = bit_count - top + 1
        spec = specs.get(bit)
        if spec is None:
            raise IpmCsvError(f'no field config for DE{bit}')
        if spec.length_size:
            length_digits = record[pos:pos + spec.length_size].translate(digits)
            if len(length_digits) != spec.length_size or not length_digits.isdigit():
                raise IpmCsvError(f'DE{bit}: invalid length prefix '
                                  f'{record[pos:pos + spec.length_size].decode(encoding, "replace")!r}')
            length = int(length_digits)
            pos += spec.length_size
        else:
            length = spec.length
        end = pos + length
        if end > len(record):
            raise IpmCsvError(f'DE{bit}: expected {length} bytes, only {len(record) - pos} available')
        fields[bit] = record[pos:end]
        pos = end
    if pos != len(record):
        raise IpmCsvError(f'{len(record) - pos} unexpected bytes after last field')
    return IpmRecord(mti=record[:4], bitmap=bitmap, fields=fields)


def make_bitmap(fields: typing.Iterable[int], secondary: bool = False) -> bytes:
    """
    Bitmap for the given field bits. The secondary bitmap is added when a field above 64 is
    present or ``secondary`` is set.
    """
    bits = set(fields)
    secondary = secondary or any(bit > 64 for bit in bits)
    bit_count = 128 if secondary else 64
    value = 0
    for bit in bits:
        value |= 1 << (bit_count - bit)
    if secondary:
        value |= 1 << (bit_count - 1)
    return value.to_bytes(bit_count // 8, 'big')


def build_record(record: IpmRecord, specs: typing.Dict[int, FieldSpec], encoding: str) -> bytes:
    """
    Build ISO8583 record bytes. Bitmap is derived from the fields present (keeping the
    secondary bitmap if the record had one).
    """
    if record.raw is not None:
        return record.raw
    secondary = bool(record.bitmap) and bool(record.bitmap[0] & 0x80)
    parts = [record.mti, make_bitmap(record.fields, secondary)]
    for bit in sorted(record.fields):
        spec = specs.get(bit)
        if spec is None:
            raise IpmCsvError(f'no field config for DE{bit}')
        value = record.fields[bit]
        if spec.length_size:
            if len(value) >= 10 ** spec.length_size:
                raise IpmCsvError(f'DE{bit}: value length {len(value)} too long for '
                                  f'{"LL" if spec.length_size == 2 else "LLL"}VAR field')
            parts.append(format(len(value), f'0{spec.length_size}d').encode(encoding))
        elif len(value) != spec.length:
            raise IpmCsvError(f'DE{bit}: value length {len(value)} must be exactly {spec.length}')
        parts.append(value)
    return b''.join(parts)


# --------------------------------------------------------------------------------------------
# file level
# --------------------------------------------------------------------------------------------

def _vbs_ends_cleanly(vbs_data: bytes) -> bool:
    """
    True if the VBS record chain reaches a zero length end of file record.
    """
    pos = 0
    while len(vbs_data) - pos >= 4:
        length = int.from_bytes(vbs_data[pos:pos + 4], 'big')
        if length == 0:
            return pos > 0
        pos += 4 + length
    return False


def is_1014_blocked(data: bytes) -> bool:
    """
    True if the data is whole 1014 blocks and either every block ends with x'4040', or the records
    only line up once the 2 byte block trailers (whatever their value, e.g. x'0000') are removed.
    """
    if len(data) < BLOCK_SIZE or len(data) % BLOCK_SIZE:
        return False
    if all(data[end - 2:end] == BLOCK_TRAILER for end in range(BLOCK_SIZE, len(data) + 1, BLOCK_SIZE)):
        return True
    return _vbs_ends_cleanly(unblock(data)[0]) and not _vbs_ends_cleanly(data)


def looks_ascii(vbs_data: bytes) -> bool:
    """
    True if the first record MTI is ASCII digits (an ASCII file rather than EBCDIC).
    """
    mti = vbs_data[4:8]
    return len(mti) == 4 and all(0x30 <= b <= 0x39 for b in mti)


def unblock(data: bytes) -> typing.Tuple[bytes, bytes, typing.Dict[int, bytes]]:
    """
    Remove 1014 blocking.

    :return: unblocked data, the block trailer used by most blocks, and the blocks whose
        trailer differs from it (keyed by block index)
    """
    blocks = [data[start:start + BLOCK_SIZE] for start in range(0, len(data), BLOCK_SIZE)]
    trailers = [block[BLOCK_DATA_SIZE:] for block in blocks]
    full = [trailer for trailer in trailers if len(trailer) == 2]
    block_trailer = max(set(full), key=full.count) if full else BLOCK_TRAILER
    exceptions = {index: trailer for index, trailer in enumerate(trailers) if trailer != block_trailer}
    return b''.join(block[:BLOCK_DATA_SIZE] for block in blocks), block_trailer, exceptions


def reblock(data: bytes, block_trailer: bytes = BLOCK_TRAILER, trailers: typing.Dict[int, bytes] = None) -> bytes:
    """
    Apply 1014 blocking to data that already includes its fill characters.

    :param block_trailer: 2 bytes ending each block
    :param trailers: blocks (by index) ending with different bytes
    """
    trailers = trailers or {}
    out = []
    for index, start in enumerate(range(0, len(data), BLOCK_DATA_SIZE)):
        out.append(data[start:start + BLOCK_DATA_SIZE])
        out.append(trailers.get(index, block_trailer))
    return b''.join(out)


def fill_to_block(vbs_data: bytes) -> bytes:
    """
    Fill to a whole number of 1012 data blocks with x'40' as the cardutil Block1014 writer does.
    """
    return vbs_data + b'\x40' * (-len(vbs_data) % BLOCK_DATA_SIZE)


def split_ipm(data: bytes, encoding: str = None,
              blocked: bool = None) -> typing.Tuple[IpmFile, typing.List[bytes]]:
    """
    Split IPM file bytes into its records (in file order) and an :class:`IpmFile` holding the
    file details. The returned IpmFile has no records yet.
    """
    if blocked is None:
        blocked = is_1014_blocked(data)
    block_trailer, trailers = BLOCK_TRAILER, {}
    vbs_data = data
    if blocked:
        vbs_data, block_trailer, trailers = unblock(data)
    if encoding is None:
        encoding = DEFAULT_ENCODING
        if looks_ascii(vbs_data):
            LOGGER.warning('first MTI looks like ASCII but encoding %s is used - '
                           'give the encoding (e.g. latin_1) if this is an ASCII file', encoding)

    ipm = IpmFile(encoding=encoding, blocked=blocked, block_trailer=block_trailer, block_trailers=trailers,
                  terminator=False)
    records = []
    view = memoryview(vbs_data)
    pos = 0
    while len(vbs_data) - pos >= 4:
        length = int.from_bytes(view[pos:pos + 4], 'big')
        if length == 0:
            ipm.terminator = True
            pos += 4
            break
        if pos + 4 + length > len(vbs_data):
            LOGGER.warning('record %s: length %s runs past end of data - kept as trailing data',
                           len(records) + 1, length)
            break
        records.append(bytes(view[pos + 4:pos + 4 + length]))
        pos += 4 + length
    ipm.tail = bytes(view[pos:])
    return ipm, records


def read_ipm(data: bytes, encoding: str = None, blocked: bool = None,
             bit_config: dict = None) -> IpmFile:
    """
    Read IPM file bytes into an :class:`IpmFile`. Never fails on bad data: records that can't be
    parsed are kept raw and unreadable data at the end is kept as ``tail``.

    :param data: the IPM file contents
    :param encoding: text encoding, default cp037
    :param blocked: 1014 blocked file, detected when not given
    :param bit_config: cardutil style bit config
    """
    specs = get_field_specs(bit_config)
    ipm, records = split_ipm(data, encoding, blocked)
    ipm.records = [_parse_or_raw(record, specs, ipm.encoding, number)
                   for number, record in enumerate(records, start=1)]
    ipm.had_header = ipm.has_header
    ipm.had_trailer = ipm.has_trailer
    return ipm


def _parse_or_raw(record_bytes, specs, encoding, record_number) -> IpmRecord:
    # A successful parse always rebuilds identically: field bytes are kept as they are, length
    # prefixes are fixed width digits, and the bitmap only has the parsed fields (plus bit 1 kept).
    # The whole file check in convert_ipm_to_csv confirms this on every conversion.
    try:
        return parse_record(record_bytes, specs, encoding)
    except IpmCsvError as ex:
        LOGGER.warning('record %s: %s - kept raw', record_number, ex)
    return IpmRecord(raw=record_bytes)


def write_ipm(ipm: IpmFile, bit_config: dict = None) -> bytes:
    """
    Build IPM file bytes from an :class:`IpmFile`.
    """
    return _finish_ipm(ipm, _vbs_records(ipm.records, get_field_specs(bit_config), ipm.encoding))


def _vbs_records(records: typing.Iterable[IpmRecord], specs, encoding: str) -> bytes:
    """
    Records as VBS data: each record prefixed with its 4 byte length.
    """
    parts = []
    for record in records:
        record_bytes = build_record(record, specs, encoding)
        parts.append(len(record_bytes).to_bytes(4, 'big'))
        parts.append(record_bytes)
    return b''.join(parts)


def _finish_ipm(ipm: IpmFile, records_data: bytes) -> bytes:
    """
    Complete VBS record data into the file: end of file record, trailing data and 1014 blocking.
    """
    vbs_data = records_data + (b'\x00\x00\x00\x00' if ipm.terminator else b'')
    if not ipm.blocked:
        return vbs_data + ipm.tail
    if (len(vbs_data) + len(ipm.tail)) % BLOCK_DATA_SIZE and not ipm.tail.strip(b'\x40'):
        # records changed size so the original fill no longer completes the last block
        return reblock(fill_to_block(vbs_data), ipm.block_trailer, ipm.block_trailers)
    return reblock(vbs_data + ipm.tail, ipm.block_trailer, ipm.block_trailers)


# --------------------------------------------------------------------------------------------
# header / trailer generation
# --------------------------------------------------------------------------------------------

@dataclass
class FileId:
    """
    PDS 0105 File ID: file type (3), file reference date YYMMDD (6), processor id (11),
    file sequence number (5).
    """
    file_type: str = '001'
    file_date: str = ''
    processor_id: str = '00000000000'
    sequence: str = '00001'

    def __str__(self):
        file_date = self.file_date or datetime.date.today().strftime('%y%m%d')
        value = f'{self.file_type:0>3}{file_date}{self.processor_id:0>11}{self.sequence:0>5}'
        if len(value) != 25 or not _is_ascii_digits(value):
            raise IpmCsvError(f'invalid File ID (PDS 0105) {value!r}: must be 25 digits')
        return value


def _pds(tag: int, value: str) -> str:
    return f'{tag:04d}{len(value):03d}{value}'


def _find_pds(de_value: str, tag: int) -> typing.Optional[str]:
    pos = 0
    while pos + 7 <= len(de_value):
        pds_tag, pds_len = de_value[pos:pos + 4], de_value[pos + 4:pos + 7]
        if not (_is_ascii_digits(pds_tag) and _is_ascii_digits(pds_len)):
            return None
        if int(pds_tag) == tag:
            return de_value[pos + 7:pos + 7 + int(pds_len)]
        pos += 7 + int(pds_len)
    return None


def _file_control_record(function_code: str, pds_data: str, message_number: int, encoding: str) -> IpmRecord:
    fields = {
        24: function_code.encode(encoding),
        48: pds_data.encode(encoding),
        71: f'{message_number:08d}'.encode(encoding),
    }
    return IpmRecord(mti=FILE_CONTROL_MTI.encode(encoding), bitmap=make_bitmap(fields, secondary=True),
                     fields=fields)


def add_header_trailer(ipm: IpmFile, file_id: FileId = None, header: bool = True, trailer: bool = True,
                       processing_mode: str = 'P') -> typing.List[str]:
    """
    Add file header (1644/697) and trailer (1644/695) records when missing.

    * header DE48: PDS 0105 File ID, PDS 0122 processing mode; DE71 message number 1
    * trailer DE48: PDS 0105, PDS 0301 file amount checksum (sum of DE4, 16 digits),
      PDS 0306 file message count (all records incl. header and trailer, 8 digits);
      DE71 message number = record count

    The File ID is taken from an existing header or trailer, otherwise from ``file_id``.

    :param header: add a header if missing
    :param trailer: add a trailer if missing
    :param processing_mode: header PDS 0122: ``P`` production or ``T`` test
    :return: list of messages describing what was added
    """
    enc = ipm.encoding
    first = ipm.records[0] if ipm.records else None
    last = ipm.records[-1] if ipm.records else None
    amount = sum(_amount(record, enc) for record in ipm.records) if trailer else 0
    header_record, trailer_record, added = _file_control_records(
        first, last, len(ipm.records), amount, enc, file_id, header, trailer, processing_mode)
    if header_record:
        ipm.records.insert(0, header_record)
    if trailer_record:
        ipm.records.append(trailer_record)
    return added


def _amount(record: IpmRecord, encoding: str) -> int:
    """
    DE4 amount of a record, 0 when it has none.
    """
    de4 = record.fields.get(4) if record.raw is None else None
    if de4:
        text = de4.decode(encoding)
        if _is_ascii_digits(text):
            return int(text)
    return 0


def _file_control_records(first: typing.Optional[IpmRecord], last: typing.Optional[IpmRecord], record_count: int,
                          amount: int, encoding: str, file_id: FileId, header: bool, trailer: bool,
                          processing_mode: str):
    """
    Header and trailer records to add (None when present or not wanted), and messages saying so.

    :param first: first record of the file
    :param last: last record of the file
    :param record_count: number of records in the file
    :param amount: sum of DE4 of all records
    """
    has_header = first is not None and first.is_file_control(encoding, HEADER_FUNCTION_CODE)
    has_trailer = last is not None and last.is_file_control(encoding, TRAILER_FUNCTION_CODE)
    need_header, need_trailer = header and not has_header, trailer and not has_trailer
    header_record = trailer_record = None
    added = []
    if not (need_header or need_trailer):
        return header_record, trailer_record, added

    existing = first if has_header else last if has_trailer else None
    file_id_value = _find_pds(existing.text(48, encoding) or '', 105) if existing else None
    if not file_id_value:
        file_id_value = str(file_id or FileId())

    if need_header:
        if processing_mode not in ('P', 'T'):
            raise IpmCsvError(f'processing mode (PDS 0122) must be P or T, not {processing_mode!r}')
        pds_data = _pds(105, file_id_value) + _pds(122, processing_mode)
        header_record = _file_control_record(HEADER_FUNCTION_CODE, pds_data, 1, encoding)
        added.append(f'file header (1644/697) with File ID {file_id_value}, processing mode {processing_mode}')

    if need_trailer:
        count = record_count + (1 if header_record else 0) + 1
        pds_data = (_pds(105, file_id_value) + _pds(301, f'{amount % 10 ** 16:016d}') +
                    _pds(306, f'{count:08d}'))
        trailer_record = _file_control_record(TRAILER_FUNCTION_CODE, pds_data, count, encoding)
        added.append(f'file trailer (1644/695): amount checksum {amount % 10 ** 16}, message count {count}')
    return header_record, trailer_record, added


# --------------------------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------------------------

def _encode_cell(value: bytes, spec: typing.Optional[FieldSpec], encoding: str) -> str:
    if spec is not None and spec.binary:
        return value.hex().upper()
    if value.translate(None, _safe_bytes(encoding)):  # has bytes that are not printable text
        return HEX_PREFIX + value.hex().upper()
    text = value.decode(encoding)
    if text.startswith(HEX_PREFIX):
        return HEX_PREFIX + value.hex().upper()
    return text


@functools.lru_cache(maxsize=None)
def _encoded_hex_prefix(encoding: str) -> bytes:
    """
    ``hex:`` in the file encoding: a CSV safe value starts with it exactly when its text does.
    """
    try:
        return HEX_PREFIX.encode(encoding)
    except UnicodeError:
        return b'\xff' * 64  # can't occur in a value of this encoding


def _decode_cell(cell: str, spec: typing.Optional[FieldSpec], encoding: str) -> bytes:
    if spec is not None and spec.binary:
        return bytes.fromhex(cell)
    if cell.startswith(HEX_PREFIX):
        return bytes.fromhex(cell[len(HEX_PREFIX):])
    return cell.encode(encoding)


def _meta_to_string(ipm: IpmFile) -> str:
    items = [
        ('cardkit', META_VERSION),
        ('encoding', ipm.encoding),
        ('blocked', int(ipm.blocked)),
        ('terminator', int(ipm.terminator)),
        ('header', int(ipm.had_header)),
        ('trailer', int(ipm.had_trailer)),
        # x'40' fill (normal for 1014 blocked files) as a count, anything else as hex
        ('fill', len(ipm.tail)) if ipm.tail and not ipm.tail.strip(b'\x40') else ('tail', ipm.tail.hex().upper()),
        ('block_trailer', ipm.block_trailer.hex().upper()),
        ('trailers', ','.join(f'{i}:{t.hex().upper()}' for i, t in sorted(ipm.block_trailers.items()))),
    ]
    return ';'.join(f'{k}={v}' for k, v in items)


def _meta_from_string(meta: str) -> dict:
    values = dict(item.split('=', 1) for item in meta.split(';') if '=' in item)
    if 'cardkit' not in values:
        raise IpmCsvError(f'META row is not a cardkit file description: {meta!r}')
    trailers = {}
    for item in filter(None, values.get('trailers', '').split(',')):
        index, trailer = item.split(':', 1)
        trailers[int(index)] = bytes.fromhex(trailer)
    return {
        'encoding': values.get('encoding', DEFAULT_ENCODING),
        'blocked': values.get('blocked') == '1',
        'terminator': values.get('terminator', '1') == '1',
        'had_header': values.get('header', '1') == '1',
        'had_trailer': values.get('trailer', '1') == '1',
        'tail': b'\x40' * int(values['fill']) if 'fill' in values else bytes.fromhex(values.get('tail', '')),
        'block_trailer': bytes.fromhex(values.get('block_trailer', BLOCK_TRAILER.hex())),
        'block_trailers': trailers,
    }


def write_csv(ipm: IpmFile, out_csv: typing.TextIO, bit_config: dict = None) -> None:
    """
    Write :class:`IpmFile` to a CSV text stream (open it with ``newline=''``).
    """
    specs = get_field_specs(bit_config)
    used_bits = sorted({bit for record in ipm.records for bit in record.fields})
    columns = ['ROW', 'MTI', 'BITMAP'] + [f'DE{bit}' for bit in used_bits] + ['RAW']
    column_binary = _column_binary(used_bits, specs)
    writer = _csv_writer(out_csv)
    writer.writerow(columns)
    writer.writerow([META_ROW] + [''] * (len(columns) - 2) + [_meta_to_string(ipm)])
    _write_record_rows(writer, ipm.records, 1, column_binary, ipm.encoding)


def _csv_writer(out_csv: typing.TextIO):
    return csv.writer(out_csv, quoting=csv.QUOTE_ALL, lineterminator='\n')


def _column_binary(used_bits, specs) -> typing.List[typing.Tuple[int, bool]]:
    return [(bit, bool(specs.get(bit) and specs[bit].binary)) for bit in used_bits]


def _write_record_rows(writer, records: typing.Iterable[IpmRecord], first_number: int,
                       column_binary: typing.List[typing.Tuple[int, bool]], encoding: str) -> None:
    safe = _safe_bytes(encoding)
    hex_prefix = _encoded_hex_prefix(encoding)
    width = len(column_binary) + 2  # MTI, BITMAP, DE columns
    for number, record in enumerate(records, start=first_number):
        if record.raw is not None:
            writer.writerow([number] + [''] * width + [record.raw.hex().upper()])
            continue
        fields = record.fields
        row = [number, _encode_cell(record.mti, None, encoding), record.bitmap.hex().upper()]
        # same rules as _encode_cell, inlined: this loop runs for every cell of the file
        row += ['' if (value := fields.get(bit)) is None
                else value.hex().upper() if binary
                else value.decode(encoding) if not value.translate(None, safe) and not value.startswith(hex_prefix)
                else HEX_PREFIX + value.hex().upper()
                for bit, binary in column_binary]
        row.append('')
        writer.writerow(row)


def read_csv(in_csv: typing.TextIO, bit_config: dict = None, encoding: str = None,
             blocked: bool = None) -> IpmFile:
    """
    Read a CSV text stream into an :class:`IpmFile`.

    File details come from the META row. Without a META row (hand made CSV) defaults are cp037,
    not blocked, with end of file marker. ``encoding`` and ``blocked`` override either.
    """
    specs = get_field_specs(bit_config)
    reader = csv.reader(in_csv)
    header = next(reader, None)
    if not header or 'MTI' not in header and 'RAW' not in header:
        raise IpmCsvError('CSV must have an MTI or RAW column')
    width, row_col, mti_col, bitmap_col, raw_col, de_columns = _csv_layout(header, specs)
    ipm = IpmFile()
    meta = None
    for line_number, row in enumerate(reader, start=2):
        if len(row) < width:
            row += [''] * (width - len(row))
        try:
            if row_col is not None and row[row_col].strip().upper() == META_ROW:
                meta = _meta_from_string(row[raw_col] if raw_col is not None else '')
                for key, value in meta.items():
                    setattr(ipm, key, value)
                continue
            ipm.records.append(_row_to_record(row, mti_col, bitmap_col, raw_col, de_columns,
                                              encoding or ipm.encoding))
        except (ValueError, UnicodeError, IpmCsvError) as ex:
            raise IpmCsvError(f'CSV line {line_number}: {ex}') from ex
    if meta is None:
        ipm.had_header = ipm.had_trailer = True  # hand made CSV: generate header/trailer if missing
    if encoding:
        ipm.encoding = encoding
    if blocked is not None:
        ipm.blocked = blocked
    return ipm


def _csv_layout(header: typing.List[str], specs):
    """
    Column positions: width, ROW, MTI, BITMAP, RAW (None when missing) and DE columns as
    (index, bit, binary, name).
    """
    position = {name: index for index, name in enumerate(header)}
    row_col, mti_col, bitmap_col, raw_col = (position.get(name) for name in ('ROW', 'MTI', 'BITMAP', 'RAW'))
    de_columns = []
    for index, name in enumerate(header):
        if name.upper().startswith('DE') and name[2:].isdigit():
            bit = int(name[2:])
            de_columns.append((index, bit, bool(specs.get(bit) and specs[bit].binary), name))
    return len(header), row_col, mti_col, bitmap_col, raw_col, de_columns


def _row_to_record(row: list, mti_col, bitmap_col, raw_col, de_columns, encoding) -> IpmRecord:
    raw = row[raw_col].strip() if raw_col is not None else ''
    if raw:
        return IpmRecord(raw=bytes.fromhex(raw))
    mti_cell = row[mti_col] if mti_col is not None else ''
    if not mti_cell:
        raise IpmCsvError('MTI is empty')
    bitmap_cell = row[bitmap_col].strip() if bitmap_col is not None else ''
    bitmap = bytes.fromhex(bitmap_cell) if bitmap_cell else b''
    fields = {}
    name = None
    try:
        for index, bit, binary, name in de_columns:
            cell = row[index]
            if not cell:
                # empty cell: field is present (and empty) only when its bit is set in BITMAP
                if bitmap and bit <= len(bitmap) * 8 and bitmap[(bit - 1) // 8] & (0x80 >> ((bit - 1) % 8)):
                    fields[bit] = b''
            elif binary:
                fields[bit] = bytes.fromhex(cell)
            elif cell.startswith(HEX_PREFIX):
                fields[bit] = bytes.fromhex(cell[len(HEX_PREFIX):])
            else:
                fields[bit] = cell.encode(encoding)
    except ValueError as ex:
        raise IpmCsvError(f'{name}: {ex}') from ex
    return IpmRecord(mti=_decode_cell(mti_cell, None, encoding), bitmap=bitmap, fields=fields)


# --------------------------------------------------------------------------------------------
# file conversion
# --------------------------------------------------------------------------------------------

@dataclass
class ConversionResult:
    records: int = 0
    raw_records: int = 0
    encoding: str = ''
    blocked: bool = False
    verified: typing.Optional[bool] = None
    sha256: str = ''
    messages: typing.List[str] = field(default_factory=list)


def resolve_workers(workers: typing.Optional[int], record_count: int) -> int:
    """
    Number of processes to use. ``None`` means automatic: one per CPU (at most 8) for files of
    at least PARALLEL_MIN_RECORDS records, otherwise 1.
    """
    if workers is None:
        workers = min(os.cpu_count() or 1, 8) if record_count >= PARALLEL_MIN_RECORDS else 1
    return max(1, workers)


def _chunks(items: list, workers: int) -> typing.List[typing.Tuple[int, list]]:
    """
    Split into consecutive chunks (start index, items) - order is kept when joined back.
    """
    size = max(1000, -(-len(items) // (workers * 4))) if workers > 1 else max(len(items), 1)
    return [(start, items[start:start + size]) for start in range(0, len(items), size)]


class _Runner:
    """
    Runs chunk jobs in order, in a process pool when more than one worker is wanted.
    """
    def __init__(self, workers: int):
        self.pool = ProcessPoolExecutor(workers) if workers > 1 else None

    def map(self, func, jobs):
        return list(self.pool.map(func, jobs) if self.pool else map(func, jobs))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.pool:
            self.pool.shutdown()


def _job_used_bits(job):
    records, first_number, encoding, bit_config = job
    specs = get_field_specs(bit_config)
    bits, raw = set(), []
    for number, record in enumerate(records, start=first_number):
        try:
            bits.update(parse_record(record, specs, encoding).fields)
        except IpmCsvError as ex:
            raw.append((number, str(ex)))
    return bits, raw


def _job_csv_rows(job):
    records, first_number, encoding, bit_config, used_bits = job
    specs = get_field_specs(bit_config)
    parsed = []
    for record in records:
        try:
            parsed.append(parse_record(record, specs, encoding))
        except IpmCsvError:
            parsed.append(IpmRecord(raw=record))
    out = io.StringIO(newline='')
    _write_record_rows(_csv_writer(out), parsed, first_number, _column_binary(used_bits, specs), encoding)
    return out.getvalue()


def _job_csv_lines_to_vbs(job):
    """
    CSV lines to VBS record data. Returns data, record count, DE4 total, first and last record,
    any META row values found, and the number of RAW records.
    """
    lines, first_line_number, header, encoding, bit_config = job
    specs = get_field_specs(bit_config)
    width, row_col, mti_col, bitmap_col, raw_col, de_columns = _csv_layout(header, specs)
    parts, metas, records = [], [], []
    count = amount = raw_count = 0
    first = last = None
    for line_number, row in enumerate(csv.reader(lines, strict=True), start=first_line_number):
        if len(row) < width:
            row += [''] * (width - len(row))
        try:
            if row_col is not None and row[row_col].strip().upper() == META_ROW:
                metas.append(row[raw_col] if raw_col is not None else '')
                continue
            record = _row_to_record(row, mti_col, bitmap_col, raw_col, de_columns, encoding)
            record_bytes = build_record(record, specs, encoding)
        except (ValueError, UnicodeError, IpmCsvError) as ex:
            raise IpmCsvError(f'CSV line {line_number}: {ex}') from ex
        parts.append(len(record_bytes).to_bytes(4, 'big'))
        parts.append(record_bytes)
        amount += _amount(record, encoding)
        count += 1
        raw_count += record.raw is not None
        first = first or record
        last = record
    return b''.join(parts), count, amount, first, last, metas, raw_count


def _csv_text_to_vbs(text: str, runner: _Runner, workers: int, encoding: typing.Optional[str],
                     bit_config: dict):
    """
    CSV text to (IpmFile with file details, VBS record data, record count, DE4 total, first, last,
    RAW record count).
    Rows are processed in chunks and joined in order.
    """
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    lines = [line + '\n' for line in lines]  # keep line ends: a quoted value may span lines
    header = next(csv.reader(lines[:1]), None)
    if not header or 'MTI' not in header and 'RAW' not in header:
        raise IpmCsvError('CSV must have an MTI or RAW column')
    ipm = IpmFile()
    meta = None
    body = lines[1:]
    # META row first so the encoding is known before rows are converted
    if body and body[0].startswith(f'"{META_ROW}"') or body and body[0].startswith(f'{META_ROW},'):
        meta_row = next(csv.reader(body[:1]))
        raw_col = header.index('RAW') if 'RAW' in header else None
        meta = _meta_from_string(meta_row[raw_col] if raw_col is not None and raw_col < len(meta_row) else '')
        body = body[1:]
    if meta:
        for key, value in meta.items():
            setattr(ipm, key, value)
    else:
        ipm.had_header = ipm.had_trailer = True  # hand made CSV: generate header/trailer if missing
    if encoding:
        ipm.encoding = encoding
    first_line = 3 if meta else 2
    jobs = [(chunk, first_line + start, header, ipm.encoding, bit_config) for start, chunk in _chunks(body, workers)]
    results = runner.map(_job_csv_lines_to_vbs, jobs)
    for result in results:
        for meta_value in result[5]:
            for key, value in _meta_from_string(meta_value).items():
                setattr(ipm, key, value)
    if encoding:
        ipm.encoding = encoding
    records_data = b''.join(result[0] for result in results)
    count = sum(result[1] for result in results)
    amount = sum(result[2] for result in results)
    firsts = [result[3] for result in results if result[3] is not None]
    lasts = [result[4] for result in results if result[4] is not None]
    raw_count = sum(result[6] for result in results)
    return (ipm, records_data, count, amount, (firsts[0] if firsts else None), (lasts[-1] if lasts else None),
            raw_count)


def _lines_safe_to_split(text: str) -> bool:
    """
    True when no quoted CSV value spans lines: every line has an even number of quote characters.
    Always true for CSVs written by cardkit (control characters are written as hex).
    """
    return not any(line.count('"') % 2 for line in text.split('\n'))


def convert_ipm_to_csv(in_filename: str, out_filename: str, encoding: str = None, blocked: bool = None,
                       bit_config: dict = None, verify: bool = True, workers: int = None) -> ConversionResult:
    """
    Convert an IPM file to CSV. With ``verify`` the written CSV is converted back and compared
    with the original file; :class:`IpmCsvError` is raised if they differ.

    Large files are processed by several processes (``workers``, automatic by default). Records
    are always written in file order.
    """
    with open(in_filename, 'rb') as in_file:
        data = in_file.read()
    ipm, records = split_ipm(data, encoding, blocked)
    workers = resolve_workers(workers, len(records))
    specs = get_field_specs(bit_config)
    if records:
        ipm.records = [_parse_or_raw(records[0], specs, ipm.encoding, 1)]
        ipm.had_header = ipm.has_header
        ipm.records = [_parse_or_raw(records[-1], specs, ipm.encoding, len(records))]
        ipm.had_trailer = ipm.has_trailer
        ipm.records = []
    else:
        ipm.had_header = ipm.had_trailer = False

    with _Runner(workers) as runner:
        chunks = _chunks(records, workers)
        used_bits, raw = set(), []
        for bits, chunk_raw in runner.map(_job_used_bits, [(chunk, start + 1, ipm.encoding, bit_config)
                                                            for start, chunk in chunks]):
            used_bits |= bits
            raw += chunk_raw
        for number, reason in raw:
            LOGGER.warning('record %s: %s - kept raw', number, reason)
        used_bits = sorted(used_bits)
        columns = ['ROW', 'MTI', 'BITMAP'] + [f'DE{bit}' for bit in used_bits] + ['RAW']
        texts = runner.map(_job_csv_rows, [(chunk, start + 1, ipm.encoding, bit_config, used_bits)
                                           for start, chunk in chunks])
        with open(out_filename, 'w', encoding='utf-8', newline='') as out_csv:
            writer = _csv_writer(out_csv)
            writer.writerow(columns)
            writer.writerow([META_ROW] + [''] * (len(columns) - 2) + [_meta_to_string(ipm)])
            out_csv.writelines(texts)

        result = ConversionResult(records=len(records), raw_records=len(raw), encoding=ipm.encoding,
                                  blocked=ipm.blocked, sha256=hashlib.sha256(data).hexdigest())
        if not ipm.had_header:
            result.messages.append('file has no header record')
        if not ipm.had_trailer:
            result.messages.append('file has no trailer record')
        if ipm.tail and not (ipm.blocked and set(ipm.tail) == {0x40}):
            result.messages.append(f'{len(ipm.tail)} bytes of trailing data kept in META row')
        if verify:
            with open(out_filename, 'r', encoding='utf-8-sig', newline='') as in_csv:
                text = in_csv.read()
            rebuilt_ipm, records_data, *_ = _csv_text_to_vbs(text, runner, workers, None, bit_config)
            result.verified = _finish_ipm(rebuilt_ipm, records_data) == data
            if not result.verified:
                raise IpmCsvError(f'verification failed: CSV {out_filename} does not rebuild {in_filename}')
    return result


def convert_csv_to_ipm(in_filename: str, out_filename: str, encoding: str = None, blocked: bool = None,
                       bit_config: dict = None, auto_header_trailer: bool = True,
                       file_id: FileId = None, processing_mode: str = 'P', workers: int = None) -> ConversionResult:
    """
    Convert a CSV to an IPM file, generating header and trailer records when missing
    (unless the CSV came from an IPM file that had none, or ``auto_header_trailer`` is False).

    Large files are processed by several processes (``workers``, automatic by default). Records
    are always written in CSV order.
    """
    with open(in_filename, 'r', encoding='utf-8-sig', newline='') as in_csv:
        text = in_csv.read()
    if not _lines_safe_to_split(text):
        workers = 1  # a quoted value spans lines (hand made CSV) - rows can't be split by line
    workers = resolve_workers(workers, text.count('\n'))
    with _Runner(workers) as runner:
        ipm, records_data, count, amount, first, last, raw_count = _csv_text_to_vbs(
            text, runner, workers, encoding, bit_config)
    if blocked is not None:
        ipm.blocked = blocked
    result = ConversionResult(encoding=ipm.encoding, blocked=ipm.blocked)
    if auto_header_trailer:
        header_record, trailer_record, result.messages = _file_control_records(
            first, last, count, amount, ipm.encoding, file_id, ipm.had_header, ipm.had_trailer, processing_mode)
        specs = get_field_specs(bit_config)
        if header_record:
            records_data = _vbs_records([header_record], specs, ipm.encoding) + records_data
            count += 1
        if trailer_record:
            records_data += _vbs_records([trailer_record], specs, ipm.encoding)
            count += 1
    data = _finish_ipm(ipm, records_data)
    with open(out_filename, 'wb') as out_file:
        out_file.write(data)
    result.records = count
    result.raw_records = raw_count
    result.sha256 = hashlib.sha256(data).hexdigest()
    return result


def ipm_bytes_to_csv_text(data: bytes, **kwargs) -> str:
    """
    Convenience: IPM bytes to CSV text.
    """
    out = io.StringIO(newline='')
    write_csv(read_ipm(data, **kwargs), out, kwargs.get('bit_config'))
    return out.getvalue()


def csv_text_to_ipm_bytes(text: str, bit_config: dict = None, **kwargs) -> bytes:
    """
    Convenience: CSV text to IPM bytes (no header/trailer generation).
    """
    return write_ipm(read_csv(io.StringIO(text, newline=''), bit_config, **kwargs), bit_config)
