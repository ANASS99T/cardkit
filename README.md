# cardkit

Lossless Mastercard IPM tooling. A drop-in replacement for [cardutil](https://github.com/adelosa/cardutil) with its bugs fixed.

**IPM → CSV → IPM gives a file identical to the original, byte for byte.** Nothing is converted, trimmed or masked.

## Install

```bash
pip install -e ".[crypto]"
```

## Convert files

```bash
cardkit ipm2csv T112.ipm -o T112.csv
```

```bash
cardkit csv2ipm T112.csv -o T112_rebuilt.ipm
```

```bash
cardkit compare T112.ipm T112_rebuilt.ipm
```

`ipm2csv` detects the encoding (ASCII/latin_1 or EBCDIC cp500) and 1014 blocking itself, then **verifies** that the CSV rebuilds the identical file. If it doesn't, it fails instead of handing you a lossy CSV. Use `--encoding`, `--blocked`/`--unblocked` or `--config-file` to override.

### What's in the CSV

| Column | Content |
|---|---|
| `ROW` | `META` for the file details row, otherwise the record number |
| `MTI` | message type, exactly as in the file |
| `BITMAP` | record bitmap in hex. A bit that is set marks the field present, even if the cell is empty |
| `DEn` | field value exactly as in the file: spaces and leading zeros kept, dates not converted. Only the fields used in the file get a column |
| `DE55` | ICC data as hex, exactly as in the file |
| `DE48`, `DE62`, `DE123`–`DE125` | the PDS data exactly as in the file |
| `RAW` | hex of a whole record that couldn't be parsed. It goes back unchanged. In the `META` row it holds the file details (encoding, blocking, end-of-file marker, trailing bytes) |

A text value that can't sit safely in a CSV (control characters, or text that itself starts with `hex:`) is written as `hex:` followed by its bytes in hex.

> Opening the CSV in Excel and saving it drops leading zeros and reformats values. Edit it with a text editor, or import every column as Text.

### Editing the CSV

You can change values. Lengths for LLVAR/LLLVAR fields are recalculated and the 1014 blocking is redone. A fixed-length field with the wrong length is **rejected**, never silently padded or cut. To remove a field, clear its cell and its bit in `BITMAP` (or clear the `BITMAP` cell to have it recalculated).

### Header and trailer generation

When the CSV has no file header (MTI 1644, DE24 `697`) or no trailer (MTI 1644, DE24 `695`), `csv2ipm` generates them:

- **header**: DE48 = PDS 0105 File ID + PDS 0122 processing mode (`--processing-mode`: `P` production, the default, or `T` test); DE71 = `00000001`
- **trailer**: DE48 = PDS 0105 + PDS 0301 (sum of all DE4 amounts, 16 digits) + PDS 0306 (message count including header and trailer, 8 digits); DE71 = message count

The File ID is copied from the existing header or trailer if there is one. Otherwise it is built from `--file-type`, `--file-date` (YYMMDD, default today), `--processor-id` and `--file-seq`. A CSV made from an IPM file that had no header or trailer remembers that, so `csv2ipm` doesn't add one. `--no-header-trailer` turns generation off.

A hand-made CSV only needs `MTI` and `DEn` columns. It is treated as latin_1, not blocked, unless you pass `--encoding` / `--blocked`.

## Python API

```python
from cardkit import ipmcsv

ipmcsv.convert_ipm_to_csv('in.ipm', 'out.csv')          # verified
ipmcsv.convert_csv_to_ipm('out.csv', 'new.ipm')

ipm = ipmcsv.read_ipm(open('in.ipm', 'rb').read())      # IpmFile: records with raw field bytes
ipm.records[1].fields[42]                               # b'MERCHANT0000001'
data = ipmcsv.write_ipm(ipm)
```

## cardutil compatibility

`cardkit.iso8583`, `cardkit.mciipm`, `cardkit.card`, `cardkit.pinblock`, `cardkit.key` and `cardkit.config` have the same API as cardutil 0.7.3. Change `cardutil` to `cardkit` in your imports. The cardutil test suite passes against cardkit. Fixes (details in [ANALYSIS.md](ANALYSIS.md)):

- messages with only a primary bitmap can be read; DE128 is processed
- values too long for a field raise an error instead of being cut off or corrupting the length prefix
- `dumps()` no longer changes the dict you pass in; too much PDS data raises a clear error
- DE55 is parsed as real BER-TLV (multi-byte tags such as `DF01`, long-form lengths)
- 10–12 digit PINs work in ISO-0/ISO-4 PIN blocks
- Luhn validation works under `python -O`; short PANs are masked safely
- `loads` is about 2.7× faster (it no longer builds a hex dump of every message when debug logging is off)

## License

MIT. Based on cardutil, Copyright (c) 2019-2025 Anthony Delosa.
