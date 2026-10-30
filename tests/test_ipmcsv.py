import io
import random

import pytest

from cardkit import mciipm
from cardkit.cli import cardkit_cli
from cardkit.ipmcsv import (
    IpmFile, IpmRecord, IpmCsvError, FileId, get_field_specs, build_record, make_bitmap, read_ipm, write_ipm,
    read_csv, write_csv, convert_ipm_to_csv, convert_csv_to_ipm, ipm_bytes_to_csv_text, csv_text_to_ipm_bytes,
    add_header_trailer)

SPECS = get_field_specs()
ICC = bytes.fromhex('9F2608A1B2C3D4E5F60718' '9F2701' '80' '9F10120110A00003220000000000000000000000FF'
                    '5F2A020978' 'DF0102AABB' '00' '0D0A' '2C22')


def rec(encoding, mti, secondary=True, **fields):
    """build record bytes from DEn=str|bytes keyword args"""
    values = {int(k[2:]): v if isinstance(v, bytes) else v.encode(encoding) for k, v in fields.items()}
    return build_record(IpmRecord(mti=mti.encode(encoding), bitmap=make_bitmap(values, secondary),
                                  fields=values), SPECS, encoding)


def sample_records(encoding):
    return [
        rec(encoding, '1644', DE24='697', DE48='01050250012610300000001234500001', DE71='00000001'),
        rec(encoding, '1240', DE2='5555444433332222', DE3='000000', DE4='000000012550', DE12='261030101112',
            DE14='2812', DE22='  1  0  1  1', DE24='200', DE26='5411', DE31='12345678901234567890123',
            DE38='AB12  ', DE42='MERCHANT0000001', DE43='SHOP  \\1 HIGH ST\\SYDNEY\\2000      NSWAUS',
            DE48='0023003POI0158030MCC' + '0' * 27 + '0165001M', DE49='036', DE55=ICC,
            DE71='00000002', DE95='', DE127='free text 0000 '),
        rec(encoding, '1240', DE2='5555444433332222', DE4='000000000000', DE24='200',
            DE48='0002003MCC0146036001 00000000000000003600000000000000', DE71='00000003'),
        rec(encoding, '1644', DE24='695',
            DE48='0105025001261030000000123450000103010160000000000012550' '0306008' '00000004', DE71='00000004'),
    ]


def vbs(records, blocked=False, terminator=True):
    out = io.BytesIO()
    writer = mciipm.VbsWriter(out, blocked=blocked)
    writer.write_many(records)
    if terminator:
        writer.close()
    elif blocked:
        writer.out_file.finalise()
    return out.getvalue()


def roundtrip(data, **kwargs):
    text = ipm_bytes_to_csv_text(data, **kwargs)
    return csv_text_to_ipm_bytes(text), text


@pytest.mark.parametrize('encoding', ['latin_1', 'cp500'])
@pytest.mark.parametrize('blocked', [False, True])
def test_roundtrip_identical(encoding, blocked):
    data = vbs(sample_records(encoding), blocked=blocked)
    rebuilt, text = roundtrip(data)
    assert rebuilt == data
    ipm = read_ipm(data)
    assert (ipm.encoding, ipm.blocked) == (encoding, blocked)
    assert all(r.raw is None for r in ipm.records)


def test_csv_shows_values_untouched():
    data = vbs(sample_records('cp500'))
    _, text = roundtrip(data)
    assert '"000000012550"' in text                     # leading zeros kept
    assert '"  1  0  1  1"' in text                     # spaces kept
    assert '"AB12  "' in text                           # trailing spaces kept
    assert '"0023003POI0158030MCC' + '0' * 27 + '0165001M"' in text  # PDS untouched
    assert f'"{ICC.hex().upper()}"' in text            # DE55 as hex exactly
    assert '"SHOP  \\1 HIGH ST\\SYDNEY\\2000      NSWAUS"' in text


def test_present_empty_llvar_kept():
    data = vbs(sample_records('latin_1'))
    ipm = read_csv(io.StringIO(ipm_bytes_to_csv_text(data), newline=''))
    assert ipm.records[1].fields[95] == b''


def test_unknown_field_kept_raw():
    record = rec('latin_1', '1240', DE2='5555444433332222') + b'X'  # trailing junk -> unparseable
    odd = b'1240' + make_bitmap([7]) + b'0101120000'                   # DE7 not in config
    data = vbs([record, odd])
    rebuilt, text = roundtrip(data)
    assert rebuilt == data
    assert sum(r.raw is not None for r in read_ipm(data).records) == 2


def test_control_chars_and_hex_prefix_escaped():
    data = vbs([rec('latin_1', '1240', DE42='ABC\x00\r\nDEF\x85\x01 XYZ', DE127='hex:ABCD'),
                rec('cp500', '1240', DE127='\x25 ¢ [] ! ^ |')])
    for encoding in ('latin_1', 'cp500'):
        rebuilt, text = roundtrip(data, encoding=encoding)
        assert rebuilt == data


def test_no_terminator_and_trailing_garbage():
    records = sample_records('latin_1')
    for data in (vbs(records, terminator=False),
                 vbs(records) + b'\x00\x01trailing junk',
                 vbs(records)[:-3],                       # truncated terminator
                 vbs(records)[:-30]):                     # truncated last record
        rebuilt, _ = roundtrip(data)
        assert rebuilt == data


def test_primary_only_and_empty_secondary_bitmaps():
    data = vbs([rec('latin_1', '0100', secondary=False, DE2='4444555566667777', DE3='000000'),
                rec('latin_1', '1240', secondary=True, DE2='4444555566667777')])
    rebuilt, text = roundtrip(data)
    assert rebuilt == data
    ipm = read_ipm(data)
    assert len(ipm.records[0].bitmap) == 8 and len(ipm.records[1].bitmap) == 16


def test_blocked_edge_cases():
    records = sample_records('latin_1')
    data = vbs(records, blocked=True)
    # non standard block trailer and a truncated final block
    odd = data[:1012] + b'\x00\x01' + data[1014:]
    for sample in (odd, data[:-500], data + b'\x40' * 1014, data[:-1]):
        rebuilt, _ = roundtrip(sample, blocked=True)
        assert rebuilt == sample
    # data ending exactly on a block boundary (cardutil adds a whole block of fill)
    filler = rec('latin_1', '1240', DE127='x' * 981)  # 4 + (4+16+3+981) + 4 = 1012
    exact = vbs([filler], blocked=True)
    assert roundtrip(exact)[0] == exact


def test_random_fuzz_roundtrip():
    rnd = random.Random(42)
    for _ in range(300):
        records = []
        for _ in range(rnd.randint(0, 6)):
            if rnd.random() < 0.5:
                records.append(bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 300))))
            else:
                records.append(rec('latin_1', '1240', DE2='4' * rnd.randint(0, 19),
                                   DE48=''.join(chr(rnd.randint(0, 255)) for _ in range(rnd.randint(0, 50))),
                                   DE55=bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 255)))))
        data = vbs(records, blocked=rnd.random() < 0.5, terminator=rnd.random() < 0.8)
        if rnd.random() < 0.2:
            data += bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 20)))
        assert roundtrip(data)[0] == data


def test_edited_csv_builds_valid_file():
    data = vbs(sample_records('cp500'), blocked=True)
    text = ipm_bytes_to_csv_text(data)
    text = text.replace('"MERCHANT0000001"', '"MERCHANT0000002"').replace('"free text 0000 "', '"much longer text ' + 'y' * 900 + '"')
    out = csv_text_to_ipm_bytes(text)
    assert len(out) % 1014 == 0
    records = list(mciipm.IpmReader(io.BytesIO(out), encoding='cp500', blocked=True))
    assert records[1]['DE42'] == 'MERCHANT0000002'
    assert records[1]['DE127'].startswith('much longer text')


def test_edited_fixed_field_wrong_length_rejected():
    text = ipm_bytes_to_csv_text(vbs(sample_records('latin_1'))).replace('"MERCHANT0000001"', '"SHORT"')
    with pytest.raises(IpmCsvError, match='DE42'):
        csv_text_to_ipm_bytes(text)


def test_file_conversion_verified(tmp_path):
    data = vbs(sample_records('cp500'), blocked=True)
    ipm_in, csv_out, ipm_out = tmp_path / 'in.ipm', tmp_path / 'out.csv', tmp_path / 'out.ipm'
    ipm_in.write_bytes(data)
    result = convert_ipm_to_csv(str(ipm_in), str(csv_out))
    assert result.verified and result.records == 4 and result.raw_records == 0
    convert_csv_to_ipm(str(csv_out), str(ipm_out))
    assert ipm_out.read_bytes() == data


# --- header / trailer generation -----------------------------------------------------------

HAND_MADE = '''MTI,DE2,DE4,DE24,DE48,DE71
1240,5555444433332222,000000012550,200,0023003POI,00000002
1240,5555444433332223,000000001000,200,0023003POI,00000003
'''


def test_header_trailer_generated_for_hand_made_csv(tmp_path):
    csv_in, ipm_out = tmp_path / 'in.csv', tmp_path / 'out.ipm'
    csv_in.write_text(HAND_MADE)
    result = convert_csv_to_ipm(str(csv_in), str(ipm_out), file_id=FileId('002', '261030', '00000012345', '00007'))
    assert len(result.messages) == 2
    records = list(mciipm.IpmReader(io.BytesIO(ipm_out.read_bytes())))
    assert [(r['MTI'], r.get('DE24')) for r in records] == [
        ('1644', '697'), ('1240', '200'), ('1240', '200'), ('1644', '695')]
    assert records[0]['PDS0105'] == '002261030000000123450000' + '7'
    assert records[0]['PDS0122'] == 'P'
    assert records[0]['DE71'] == 1 and records[-1]['DE71'] == 4
    assert records[-1]['PDS0105'] == records[0]['PDS0105']
    assert records[-1]['PDS0301'] == '0000000000013550'
    assert records[-1]['PDS0306'] == '00000004'


def test_only_missing_trailer_generated_using_header_file_id(tmp_path):
    records = sample_records('latin_1')[:-1]
    ipm = read_ipm(vbs(records))
    ipm.had_trailer = True
    added = add_header_trailer(ipm)
    assert len(added) == 1 and 'trailer' in added[0]
    trailer = ipm.records[-1].fields[48].decode()
    assert trailer.startswith('01050250012610300000001234500001')
    assert trailer.endswith('0306008' '00000004')


def test_no_generation_when_source_had_none():
    data = vbs(sample_records('latin_1')[1:3])  # no header / trailer in original
    text = ipm_bytes_to_csv_text(data)
    assert 'header=0' in text and 'trailer=0' in text


def test_no_generation_when_source_had_none_file(tmp_path):
    data = vbs(sample_records('latin_1')[1:3])
    ipm_in, csv_out, ipm_out = tmp_path / 'in.ipm', tmp_path / 'out.csv', tmp_path / 'out.ipm'
    ipm_in.write_bytes(data)
    convert_ipm_to_csv(str(ipm_in), str(csv_out))
    result = convert_csv_to_ipm(str(csv_out), str(ipm_out))
    assert result.messages == [] and ipm_out.read_bytes() == data


def test_deleted_header_and_trailer_rows_regenerated():
    data = vbs(sample_records('latin_1'))
    lines = ipm_bytes_to_csv_text(data).splitlines(keepends=True)
    trimmed = ''.join(lines[:2] + lines[3:-1])  # drop header (row 1) and trailer (row 4)
    ipm = read_csv(io.StringIO(trimmed, newline=''))
    add_header_trailer(ipm, header=ipm.had_header, trailer=ipm.had_trailer)
    assert ipm.has_header and ipm.has_trailer and len(ipm.records) == 4


# --- CLI -----------------------------------------------------------------------------------

def test_cli_roundtrip(tmp_path, capsys):
    data = vbs(sample_records('cp500'), blocked=True)
    (tmp_path / 'f.ipm').write_bytes(data)
    assert cardkit_cli.cli_run(['ipm2csv', str(tmp_path / 'f.ipm')]) == 0
    assert cardkit_cli.cli_run(['csv2ipm', str(tmp_path / 'f.ipm.csv'), '-o', str(tmp_path / 'g.ipm')]) == 0
    assert cardkit_cli.cli_run(['compare', str(tmp_path / 'f.ipm'), str(tmp_path / 'g.ipm')]) == 0
    assert 'verified' in capsys.readouterr().out


def test_blocked_with_zero_block_trailers():
    """some producers end each 1014 block with x'0000' instead of x'4040'"""
    records = sample_records('cp500')
    standard = vbs(records[:1] + records[1:3] * 3 + records[3:], blocked=True)
    data = b''.join(standard[i:i + 1012] + b'\x00\x00' for i in range(0, len(standard), 1014))
    ipm = read_ipm(data)
    assert ipm.blocked and ipm.block_trailer == b'\x00\x00' and ipm.block_trailers == {}
    assert len(ipm.records) == 8 and all(r.raw is None for r in ipm.records)
    rebuilt, text = roundtrip(data)
    assert rebuilt == data and 'block_trailer=0000' in text
    # edited records are reblocked with the same trailer
    edited = csv_text_to_ipm_bytes(text.replace('"free text 0000 "', '"' + 'z' * 600 + '"'))
    assert len(edited) % 1014 == 0
    assert {edited[i - 2:i] for i in range(1014, len(edited) + 1, 1014)} == {b'\x00\x00'}


def test_header_processing_mode(tmp_path):
    csv_in, ipm_out = tmp_path / 'in.csv', tmp_path / 'out.ipm'
    csv_in.write_text(HAND_MADE)
    assert cardkit_cli.cli_run(['csv2ipm', str(csv_in), '-o', str(ipm_out), '--processing-mode', 'T']) == 0
    header = next(iter(mciipm.IpmReader(io.BytesIO(ipm_out.read_bytes()))))
    assert header['PDS0122'] == 'T'
    ipm = read_csv(io.StringIO(HAND_MADE, newline=''))
    with pytest.raises(IpmCsvError, match='PDS 0122'):
        add_header_trailer(ipm, processing_mode='X')
