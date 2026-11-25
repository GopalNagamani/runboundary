#!/usr/bin/env python3
"""Write an explicit Freebuff adapter manifest; never read credential contents."""
import argparse
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--freebuff-home', type=Path, default=Path.home() / '.config/manicode')
    args = parser.parse_args()
    base = args.freebuff_home.absolute()
    files = []
    for name, kind, required in [
        ('credentials.json', 'credential', True),
        ('device-key.json', 'credential', True),
        ('freebuff', 'executable', True),
        ('freebuff-metadata.json', 'cache', False),
        ('rg', 'executable', False),
        ('tree-sitter.wasm', 'cache', False),
    ]:
        source = base / name
        if source.is_symlink() or not source.is_file():
            if required:
                parser.error(f'Required regular file missing or symlinked: {source}. Run Freebuff outside RunBoundary and log in first.')
            continue
        info = source.stat()
        mask = 0o077 if kind == 'credential' else 0o022
        if info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & mask:
            parser.error(f'Unsafe ownership, permissions, or links: {source}. Credentials require chmod 600; caches must not be writable by others.')
        files.append({'source': str(source), 'destination': f'.config/manicode/{name}', 'kind': kind})
    manifest = {'version': 1, 'agent': 'freebuff', 'terminal': {'COLORTERM': 'truecolor', 'COLORFGBG': '15;0'}, 'files': files}
    # Exclusive creation: never overwrite an existing approval manifest or follow
    # a final symlink. RunBoundary separately validates its complete path on load.
    output = args.output.absolute()
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(manifest, stream, indent=2)
        stream.write('\n')
    print(f'Created {output}. Only named files will be imported; no host settings or history included.')


if __name__ == '__main__':
    main()
