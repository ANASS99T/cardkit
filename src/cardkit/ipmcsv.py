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
import hashlib
import io
import logging
import typing
from dataclasses import dataclass, field

from cardkit import CardutilError
from cardkit.config import config as default_config

LOGGER = logging.getLogger(__name__)

HEX_PREFIX = 'hex:'
BLOCK_DATA_SIZE = 1012
BLOCK_SIZE = 1014
BLOCK_TRAILER = b'\x40\x40'
META_ROW = 'META'
META_VERSION = '1'
HEADER_FUNCTION_CODE = '697'
TRAILER_FUNCTION_CODE = '695'
FILE_CONTROL_MTI = '1644'


class IpmCsvError(CardutilError):
    pass


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
    encoding: str = 'latin_1'
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
    bits = int.from_bytes(bitmap, 'big')
    bit_count = bitmap_size * 8
    pos = 4 + bitmap_size
    fields = {}
    for bit in range(2, bit_count + 1):
        if not (bits >> (bit_count - bit)) & 1:
            continue
        spec = specs.get(bit)
        if spec is None:
            raise IpmCsvError(f'no field config for DE{bit}')
        if spec.length_size:
            length_text = record[pos:pos + spec.length_size].decode(encoding)
            if len(length_text) != spec.length_size or not _is_ascii_digits(length_text):
                raise IpmCsvError(f'DE{bit}: invalid length prefix {length_text!r}')
            length = int(length_text)
            pos += spec.length_size
        else:
            length = spec.length
        value = record[pos:pos + length]
        if len(value) != length:
            raise IpmCsvError(f'DE{bit}: expected {length} bytes, only {len(value)} available')
        fields[bit] = value
        pos += length
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


def detect_encoding(vbs_data: bytes) -> str:
    """
    Guess encoding from first record MTI: ASCII digits -> latin_1, EBCDIC digits -> cp500.
    """
    mti = vbs_data[4:8]
    if all(0x30 <= b <= 0x39 for b in mti):
        return 'latin_1'
    if mti and all(0xF0 <= b <= 0xF9 for b in mti):
        return 'cp500'
    return 'latin_1'


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


def read_ipm(data: bytes, encoding: str = None, blocked: bool = None,
             bit_config: dict = None) -> IpmFile:
    """
    Read IPM file bytes into an :class:`IpmFile`. Never fails on bad data: records that can't be
    parsed are kept raw and unreadable data at the end is kept as ``tail``.

    :param data: the IPM file contents
    :param encoding: text encoding, detected from first MTI when not given
    :param blocked: 1014 blocked file, detected when not given
    :param bit_config: cardutil style bit config
    """
    specs = get_field_specs(bit_config)
    if blocked is None:
        blocked = is_1014_blocked(data)
    block_trailer, trailers = BLOCK_TRAILER, {}
    vbs_data = data
    if blocked:
        vbs_data, block_trailer, trailers = unblock(data)
    if encoding is None:
        encoding = detect_encoding(vbs_data)

    ipm = IpmFile(encoding=encoding, blocked=blocked, block_trailer=block_trailer, block_trailers=trailers,
                  terminator=False)
    view = memoryview(vbs_data)
    pos = 0
    while True:
        if len(vbs_data) - pos < 4:
            break
        length = int.from_bytes(view[pos:pos + 4], 'big')
        if length == 0:
            ipm.terminator = True
            pos += 4
            break
        if pos + 4 + length > len(vbs_data):
            LOGGER.warning('record %s: length %s runs past end of data - kept as trailing data',
                           len(ipm.records) + 1, length)
            break
        record_bytes = bytes(view[pos + 4:pos + 4 + length])
        pos += 4 + length
        ipm.records.append(_parse_or_raw(record_bytes, specs, encoding, len(ipm.records) + 1))
    ipm.tail = bytes(view[pos:])
    ipm.had_header = ipm.has_header
    ipm.had_trailer = ipm.has_trailer
    return ipm


def _parse_or_raw(record_bytes, specs, encoding, record_number) -> IpmRecord:
    try:
        record = parse_record(record_bytes, specs, encoding)
        if build_record(record, specs, encoding) == record_bytes:
            return record
        LOGGER.warning('record %s: does not rebuild identically - kept raw', record_number)
    except (IpmCsvError, UnicodeError) as ex:
        LOGGER.warning('record %s: %s - kept raw', record_number, ex)
    return IpmRecord(raw=record_bytes)


def write_ipm(ipm: IpmFile, bit_config: dict = None) -> bytes:
    """
    Build IPM file bytes from an :class:`IpmFile`.
    """
    specs = get_field_specs(bit_config)
    parts = []
    for record in ipm.records:
        record_bytes = build_record(record, specs, ipm.encoding)
        parts.append(len(record_bytes).to_bytes(4, 'big'))
        parts.append(record_bytes)
    if ipm.terminator:
        parts.append(b'\x00\x00\x00\x00')
    vbs_data = b''.join(parts)
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
    added = []
    enc = ipm.encoding
    need_header, need_trailer = header and not ipm.has_header, trailer and not ipm.has_trailer
    if not (need_header or need_trailer):
        return added

    existing = ipm.records[0] if ipm.has_header else ipm.records[-1] if ipm.has_trailer else None
    file_id_value = _find_pds(existing.text(48, enc) or '', 105) if existing else None
    if not file_id_value:
        file_id_value = str(file_id or FileId())

    if need_header:
        if processing_mode not in ('P', 'T'):
            raise IpmCsvError(f'processing mode (PDS 0122) must be P or T, not {processing_mode!r}')
        pds_data = _pds(105, file_id_value) + _pds(122, processing_mode)
        ipm.records.insert(0, _file_control_record(HEADER_FUNCTION_CODE, pds_data, 1, enc))
        added.append(f'file header (1644/697) with File ID {file_id_value}, processing mode {processing_mode}')

    if need_trailer:
        amount = 0
        for record in ipm.records:
            de4 = record.text(4, enc) if record.raw is None else None
            if de4 and _is_ascii_digits(de4):
                amount += int(de4)
        count = len(ipm.records) + 1
        pds_data = (_pds(105, file_id_value) + _pds(301, f'{amount % 10 ** 16:016d}') +
                    _pds(306, f'{count:08d}'))
        ipm.records.append(_file_control_record(TRAILER_FUNCTION_CODE, pds_data, count, enc))
        added.append(f'file trailer (1644/695): amount checksum {amount % 10 ** 16}, message count {count}')
    return added


# --------------------------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------------------------

def _encode_cell(value: bytes, spec: typing.Optional[FieldSpec], encoding: str) -> str:
    if spec is not None and spec.binary:
        return value.hex().upper()
    try:
        text = value.decode(encoding)
    except UnicodeError:
        return HEX_PREFIX + value.hex().upper()
    if (text.startswith(HEX_PREFIX) or text.encode(encoding) != value
            or not all(ch == ' ' or ch.isprintable() for ch in text)):
        return HEX_PREFIX + value.hex().upper()
    return text


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
        'encoding': values.get('encoding', 'latin_1'),
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
    writer = csv.writer(out_csv, quoting=csv.QUOTE_ALL, lineterminator='\n')
    writer.writerow(columns)
    writer.writerow([META_ROW] + [''] * (len(columns) - 2) + [_meta_to_string(ipm)])
    for number, record in enumerate(ipm.records, start=1):
        if record.raw is not None:
            writer.writerow([number] + [''] * (len(columns) - 2) + [record.raw.hex().upper()])
            continue
        row = [number, _encode_cell(record.mti, None, ipm.encoding), record.bitmap.hex().upper()]
        for bit in used_bits:
            value = record.fields.get(bit)
            row.append('' if value is None else _encode_cell(value, specs.get(bit), ipm.encoding))
        row.append('')
        writer.writerow(row)


def read_csv(in_csv: typing.TextIO, bit_config: dict = None, encoding: str = None,
             blocked: bool = None) -> IpmFile:
    """
    Read a CSV text stream into an :class:`IpmFile`.

    File details come from the META row. Without a META row (hand made CSV) defaults are latin_1,
    not blocked, with end of file marker. ``encoding`` and ``blocked`` override either.
    """
    specs = get_field_specs(bit_config)
    reader = csv.DictReader(in_csv)
    if not reader.fieldnames or 'MTI' not in reader.fieldnames and 'RAW' not in reader.fieldnames:
        raise IpmCsvError('CSV must have an MTI or RAW column')
    de_columns = []
    for name in reader.fieldnames:
        if name.upper().startswith('DE') and name[2:].isdigit():
            de_columns.append((name, int(name[2:])))
    ipm = IpmFile()
    meta = None
    for line_number, row in enumerate(reader, start=2):
        try:
            if (row.get('ROW') or '').strip().upper() == META_ROW:
                meta = _meta_from_string(row.get('RAW') or '')
                for key, value in meta.items():
                    setattr(ipm, key, value)
                continue
            if encoding:
                ipm.encoding = encoding
            ipm.records.append(_row_to_record(row, de_columns, specs, ipm.encoding))
        except (ValueError, UnicodeError, IpmCsvError) as ex:
            raise IpmCsvError(f'CSV line {line_number}: {ex}') from ex
    if meta is None:
        ipm.had_header = ipm.had_trailer = True  # hand made CSV: generate header/trailer if missing
    if encoding:
        ipm.encoding = encoding
    if blocked is not None:
        ipm.blocked = blocked
    return ipm


def _row_to_record(row: dict, de_columns, specs, encoding) -> IpmRecord:
    raw = (row.get('RAW') or '').strip()
    if raw:
        return IpmRecord(raw=bytes.fromhex(raw))
    mti_cell = row.get('MTI') or ''
    if not mti_cell:
        raise IpmCsvError('MTI is empty')
    bitmap_cell = (row.get('BITMAP') or '').strip()
    bitmap = bytes.fromhex(bitmap_cell) if bitmap_cell else b''
    bitmap_bits = int.from_bytes(bitmap, 'big') if bitmap else 0
    bit_count = len(bitmap) * 8
    fields = {}
    for column, bit in de_columns:
        cell = row.get(column) or ''
        in_bitmap = bitmap and bit <= bit_count and (bitmap_bits >> (bit_count - bit)) & 1
        if cell == '' and not in_bitmap:
            continue
        try:
            fields[bit] = _decode_cell(cell, specs.get(bit), encoding)
        except ValueError as ex:
            raise IpmCsvError(f'{column}: {ex}') from ex
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


def convert_ipm_to_csv(in_filename: str, out_filename: str, encoding: str = None, blocked: bool = None,
                       bit_config: dict = None, verify: bool = True) -> ConversionResult:
    """
    Convert an IPM file to CSV. With ``verify`` the written CSV is converted back in memory and
    compared with the original file; :class:`IpmCsvError` is raised if they differ.
    """
    with open(in_filename, 'rb') as in_file:
        data = in_file.read()
    ipm = read_ipm(data, encoding=encoding, blocked=blocked, bit_config=bit_config)
    with open(out_filename, 'w', encoding='utf-8', newline='') as out_csv:
        write_csv(ipm, out_csv, bit_config)

    result = ConversionResult(
        records=len(ipm.records), raw_records=sum(r.raw is not None for r in ipm.records),
        encoding=ipm.encoding, blocked=ipm.blocked, sha256=hashlib.sha256(data).hexdigest())
    if not ipm.had_header:
        result.messages.append('file has no header record')
    if not ipm.had_trailer:
        result.messages.append('file has no trailer record')
    if ipm.tail and not (ipm.blocked and set(ipm.tail) == {0x40}):
        result.messages.append(f'{len(ipm.tail)} bytes of trailing data kept in META row')
    if verify:
        with open(out_filename, 'r', encoding='utf-8-sig', newline='') as in_csv:
            rebuilt = write_ipm(read_csv(in_csv, bit_config), bit_config)
        result.verified = rebuilt == data
        if not result.verified:
            raise IpmCsvError(f'verification failed: CSV {out_filename} does not rebuild {in_filename}')
    return result


def convert_csv_to_ipm(in_filename: str, out_filename: str, encoding: str = None, blocked: bool = None,
                       bit_config: dict = None, auto_header_trailer: bool = True,
                       file_id: FileId = None, processing_mode: str = 'P') -> ConversionResult:
    """
    Convert a CSV to an IPM file, generating header and trailer records when missing
    (unless the CSV came from an IPM file that had none, or ``auto_header_trailer`` is False).
    """
    with open(in_filename, 'r', encoding='utf-8-sig', newline='') as in_csv:
        ipm = read_csv(in_csv, bit_config, encoding=encoding, blocked=blocked)
    result = ConversionResult(encoding=ipm.encoding, blocked=ipm.blocked)
    if auto_header_trailer:
        result.messages += add_header_trailer(ipm, file_id, header=ipm.had_header, trailer=ipm.had_trailer,
                                              processing_mode=processing_mode)
    data = write_ipm(ipm, bit_config)
    with open(out_filename, 'wb') as out_file:
        out_file.write(data)
    result.records = len(ipm.records)
    result.raw_records = sum(r.raw is not None for r in ipm.records)
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
