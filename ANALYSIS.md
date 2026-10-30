# cardutil 0.7.3 — Analysis

Source: PyPI sdist `cardutil-0.7.3` (~2,900 lines of library code, ~1,200 lines of tests).
Every bug below was reproduced with a probe script against the installed package.

## What the library does

| Module | Purpose |
|---|---|
| `iso8583.py` | `loads`/`dumps` ISO 8583 messages ⇄ `dict` (MTI, `DEn`, `PDSnnnn`, `TAGxxxx`, `DE43_*`) |
| `config.py` | One global dict: Mastercard bit config, CSV columns, IPM parameter table layouts |
| `mciipm.py` | Mastercard IPM clearing files: VBS records, 1014 blocking, `IpmReader/Writer`, parameter extracts |
| `pinblock.py` | ISO‑0 / ISO‑4 PIN blocks, 3DES/AES encryption mixins, Visa PVV |
| `key.py` | Key component XOR, KCV, 3DES key encryption |
| `card.py` | Luhn check digit, PAN masking |
| `cli/` | `mci_ipm_to_csv`, `mci_csv_to_ipm`, param extract tools, `mideu` compat |

## Confirmed bugs

| # | Area | Problem | Reproduction result |
|---|---|---|---|
| 1 | Bitmap | Always reads a 16‑byte bitmap, ignoring bit 1. Standard primary‑only (8‑byte) messages are unparseable | `No bit config available for bit 67` |
| 2 | Bitmap | Loops are `range(2, 128)` → **DE128 is never encoded or decoded** | `dumps({'DE128': ...})` silently drops it |
| 3 | Encode | Fixed fields longer than spec are **silently truncated** (data loss) | `DE3='12345678'` → `'123456'` |
| 4 | Encode | No max length on LLVAR/LLLVAR; a 120‑char LLVAR writes a 3‑digit length → corrupt message | Round‑trip fails |
| 5 | Encode | `decimal` type keeps the decimal point | DE4 `12.50` → `000000012.50` |
| 6 | Encode | `dumps()` **mutates the caller's dict** (adds `DE48`) | Input dict changed |
| 7 | Encode | More PDS data than available PDS DEs crashes | `IndexError: pop from empty list` |
| 8 | Encode | PDS length uses `len(str)`, not encoded byte length (breaks multi‑byte encodings) | — |
| 9 | Encode | Datetime fields can't accept the raw wire string (`'201231120000'`) | `ValueError: Invalid isoformat string` |
| 10 | ICC/DE55 | Not real BER‑TLV: only `9F`/`5F` treated as 2‑byte tags (misses `DF`, `BF`, `7F`, 3‑byte tags); 1‑byte length only (no `0x81`/`0x82`); constructed tags not recursed | `DF01…` parsed as tag `DF`, rest lost |
| 11 | PIN | 10–12 digit PINs break ISO‑0 and ISO‑4 (length nibble written as decimal, read with `int()`) | PIN `123456789012` decodes as `'2'` |
| 12 | PIN | ISO‑4 `random_value=0` treated as "not given"; no validation of format nibble / fill on decode | — |
| 13 | Card | `validate_check_digit` uses `assert` → disabled under `python -O`, returns nothing | — |
| 14 | Card | `mask()` on PANs < 10 digits leaks/duplicates digits | `mask('12345678')` → `'1234565678'` |
| 15 | Keys | Key component XOR hard‑coded to 16‑byte keys (no triple‑length, no AES) | — |

## Design weaknesses

- **Performance**: `LOGGER.debug("...", hexdump(message))` computes a hex dump on *every* message even with logging off — ~60% of `loads` time. Field parsing re‑slices the remaining buffer each field; bitmap goes through string formatting. Measured: **~18.5k msg/s loads, ~33k msg/s dumps**.
- **Only text encodings**: no BCD / binary numeric fields or binary length prefixes — so Visa Base I, many host‑to‑host and most auth specs (packed BCD) are unsupported. Mastercard‑clearing‑only in practice.
- **Untyped, dict‑everything**: no dataclasses/models, no type checking, field specs are loose dicts validated nowhere. Config is a global mutable dict.
- **Errors**: one generic exception with optional kwargs; no field/offset in errors; ICC errors are swallowed into warnings by default.
- **Lossy decode**: PAN masking and `PAN-PREFIX` happen inside the parser, so a decoded message can't be re‑encoded faithfully.
- **No validation layer**: no checks of numeric fields (`n`), alphabetic (`a`), lengths, MTI structure.
- **Bundled vendored `hexdump`**, hand‑rolled `BitArray` (int/str conversions).
- **Limited crypto**: no ISO‑1/ISO‑3 PIN blocks, no CVV/CVC, no DUKPT, no TR‑31 key blocks, no ARQC.

## What it does well (keep)

- Simple `loads`/`dumps` API mirroring `json`.
- Streaming VBS / 1014‑blocked readers and writers for IPM files.
- Mastercard PDS and DE43 sub‑field breakdown.
- Configurable field specs; CLI tools for IPM ⇄ CSV.

## Results: cardkit vs cardutil

Test file: 50,002 records, EBCDIC (cp500), 1014-blocked, 11.2 MB. It has a header, a trailer, DE55 ICC data, PDS in DE48, and fields with spaces and leading zeros.

| | cardutil 0.7.3 | cardkit 0.1.0 |
|---|---|---|
| IPM → CSV | 6.7 s | 2.4 s (includes a full verification pass) |
| CSV → IPM | 3.5 s | 0.6 s |
| Rebuilt file | 8.3 MB, **different** from byte 72 | **identical** (same sha256) |
| What cardutil loses | DE4 leading zeros (`12550`), DE12 turned into `2026-10-30 10:11:12`, DE71 `1`, DE55, DE43 and DE127 left out | nothing |
| `iso8583.loads` | 18.5k msg/s | 51k msg/s |
