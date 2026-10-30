"""
cardkit command line.

::

    cardkit ipm2csv  in.ipm [-o out.csv]      # lossless, verified
    cardkit csv2ipm  in.csv [-o out.ipm]      # header/trailer generated when missing
    cardkit compare  a.ipm b.ipm              # byte compare two files
"""
import argparse
import hashlib
import logging
import sys

from cardkit import __version__
from cardkit.cli import get_config
from cardkit.ipmcsv import IpmCsvError, FileId, convert_ipm_to_csv, convert_csv_to_ipm


def cli_entry():
    return cli_run(sys.argv[1:])


def cli_parser():
    parser = argparse.ArgumentParser(prog='cardkit', description='Lossless Mastercard IPM tools')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--debug', action='store_true')
    commands = parser.add_subparsers(dest='command', required=True)

    def common(sub):
        sub.add_argument('in_filename')
        sub.add_argument('-o', '--out-filename')
        sub.add_argument('--encoding', help='file encoding (default: detected, or from CSV META row)')
        blocked = sub.add_mutually_exclusive_group()
        blocked.add_argument('--blocked', dest='blocked', action='store_true', default=None,
                             help='1014 blocked IPM file')
        blocked.add_argument('--unblocked', dest='blocked', action='store_false', help='plain VBS IPM file')
        sub.add_argument('--config-file', help='cardutil/cardkit JSON configuration (bit_config)')

    to_csv = commands.add_parser('ipm2csv', help='convert IPM file to CSV (lossless)')
    common(to_csv)
    to_csv.add_argument('--no-verify', dest='verify', action='store_false',
                        help='skip checking that the CSV rebuilds the identical IPM file')

    to_ipm = commands.add_parser('csv2ipm', help='convert CSV to IPM file')
    common(to_ipm)
    to_ipm.add_argument('--no-header-trailer', dest='auto_header_trailer', action='store_false',
                        help='do not generate missing header/trailer records')
    to_ipm.add_argument('--file-type', default='001', help='generated File ID (PDS 0105): file type, 3 digits')
    to_ipm.add_argument('--file-date', default='', help='generated File ID: date YYMMDD (default today)')
    to_ipm.add_argument('--processor-id', default='00000000000', help='generated File ID: processor id, 11 digits')
    to_ipm.add_argument('--file-seq', default='00001', help='generated File ID: sequence number, 5 digits')

    compare = commands.add_parser('compare', help='byte compare two files')
    compare.add_argument('first')
    compare.add_argument('second')
    return parser


def cli_run(argv):
    args = cli_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING, format='%(levelname)s: %(message)s')
    try:
        if args.command == 'compare':
            return compare_files(args.first, args.second)
        bit_config = get_config('cardkit.json', cli_filename=args.config_file)['bit_config']
        if args.command == 'ipm2csv':
            out = args.out_filename or args.in_filename + '.csv'
            result = convert_ipm_to_csv(args.in_filename, out, encoding=args.encoding, blocked=args.blocked,
                                        bit_config=bit_config, verify=args.verify)
        else:
            out = args.out_filename or args.in_filename + '.ipm'
            file_id = FileId(args.file_type, args.file_date, args.processor_id, args.file_seq)
            result = convert_csv_to_ipm(args.in_filename, out, encoding=args.encoding, blocked=args.blocked,
                                        bit_config=bit_config, auto_header_trailer=args.auto_header_trailer,
                                        file_id=file_id)
    except (IpmCsvError, OSError) as ex:
        print(f'cardkit: error: {ex}', file=sys.stderr)
        return 1

    print(f'{args.in_filename} -> {out}')
    print(f'  records: {result.records} ({result.raw_records} kept raw)')
    print(f'  encoding: {result.encoding}, 1014 blocked: {result.blocked}')
    for message in result.messages:
        print(f'  note: {message}')
    if result.verified:
        print(f'  verified: CSV rebuilds identical IPM (sha256 {result.sha256})')
    elif args.command == 'csv2ipm':
        print(f'  sha256: {result.sha256}')
    return 0


def compare_files(first, second):
    with open(first, 'rb') as f1, open(second, 'rb') as f2:
        a, b = f1.read(), f2.read()
    if a == b:
        print(f'identical ({len(a)} bytes, sha256 {hashlib.sha256(a).hexdigest()})')
        return 0
    offset = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
    print(f'DIFFERENT: sizes {len(a)} / {len(b)}, first difference at byte offset {offset}')
    return 1


if __name__ == '__main__':
    sys.exit(cli_entry())
