#!/usr/bin/env python3
"""Install a dedicated Hermes runtime in a macOS Homebrew tree (no login import)."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile


def plan(source, brew_root):
    if not source.is_absolute() or not (source / 'pyproject.toml').is_file():
        raise ValueError('Hermes source must be an absolute directory containing pyproject.toml')
    if brew_root not in (Path('/opt/homebrew'), Path('/usr/local')):
        raise ValueError('Use the existing Homebrew root /opt/homebrew or /usr/local')
    prefix = brew_root / 'opt/runboundary-hermes'
    launcher = brew_root / 'bin/hermes'
    if prefix.exists() or prefix.is_symlink():
        raise ValueError(f'Refusing to overwrite existing runtime: {prefix}')
    if launcher.exists() or launcher.is_symlink():
        raise ValueError(f'Refusing to overwrite existing launcher: {launcher}')
    return prefix, launcher


def validate_archive(members):
    selected = []
    for member in members:
        path = Path(member.name)
        if path.is_absolute() or '..' in path.parts or member.isdev() or member.isfifo() or member.islnk():
            raise ValueError('Unsafe entry in Hermes source archive')
        excluded = any((name.startswith('.env') and name not in ('.env.example', '.env.sample')) or name in ('auth.json', 'credentials.json', 'device-key.json', '.git', '.ssh', '.aws') or name.endswith(('.key', '.p12', '.pfx')) for name in path.parts)
        if excluded:
            continue
        if member.issym():
            # Keep all copied runtime links self-contained; refuse external ones.
            depth = len(path.parent.parts)
            target = Path(member.linkname)
            if target.is_absolute():
                raise ValueError('Absolute link in Hermes source archive')
            for part in target.parts:
                depth += -1 if part == '..' else (0 if part == '.' else 1)
                if depth < 0:
                    raise ValueError('Escaping link in Hermes source archive')
        selected.append(member)
    return selected


def install(source, brew_root, prefix, launcher):
    python = brew_root / 'bin/python3.14'
    if not python.is_file():
        raise ValueError('Homebrew Python 3.14 is required. Run: brew install python@3.14')
    # No host login HOME, API keys, PYTHONPATH, pip config or agent state reaches
    # package subprocesses. Dependency installation still needs network access.
    with tempfile.TemporaryDirectory(prefix='runboundary-hermes-install-') as directory:
        env = {
            'HOME': directory, 'TMPDIR': directory,
            'PATH': f'{brew_root}/bin:/usr/bin:/bin:/usr/sbin:/sbin',
            'PIP_CONFIG_FILE': os.devnull, 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
            'PYTHONNOUSERSITE': '1', 'LANG': 'en_US.UTF-8',
        }
        prefix.parent.mkdir(parents=True, exist_ok=True)
        prefix.mkdir(mode=0o755)  # Exclusive: do not mutate an existing runtime.
        try:
            snapshot = prefix / 'src'
            snapshot.mkdir()
            archive = Path(directory) / 'source.tar'
            subprocess.run(['/usr/bin/git', '-C', str(source), 'archive', '--format=tar', '-o', str(archive), 'HEAD'], env=env, check=True)
            with tarfile.open(archive) as bundle:
                selected = validate_archive(bundle.getmembers())
                bundle.extractall(snapshot, members=selected, filter='data')
            subprocess.run([str(python), '-I', '-m', 'venv', '--copies', str(prefix)], env=env, check=True)
            interpreter = prefix / 'bin/python'
            subprocess.run([str(interpreter), '-I', '-m', 'pip', 'install', '--no-cache-dir', '-e', str(snapshot)], env=env, check=True)
            # Hermes explicitly supports editable installs. The editable target
            # is our dedicated runtime snapshot, never the host home checkout.
            subprocess.run([str(interpreter), '-I', '-c',
                'import hermes_cli, pathlib, sys; p=pathlib.Path(hermes_cli.__file__).resolve(); '
                'assert p.is_relative_to(pathlib.Path(sys.prefix).resolve()), "Hermes escaped dedicated runtime"'], env=env, check=True)
            target = prefix / 'bin/hermes'
            if not target.is_file():
                raise ValueError('Hermes package did not install its console entry point')
            # Relative link is inside the approved runtime root. Exclusive symlink
            # creation refuses any launcher that appeared while pip was running.
            launcher.symlink_to(Path('../opt/runboundary-hermes/bin/hermes'))
        except BaseException:
            # Only the fresh dedicated runtime is removed; never touch the host
            # source installation, authentication, or another existing launcher.
            if prefix.is_dir():
                shutil.rmtree(prefix)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path.home() / '.hermes/hermes-agent')
    parser.add_argument('--homebrew-root', type=Path, default=Path('/opt/homebrew'))
    parser.add_argument('--plan', action='store_true', help='Show installation paths without installing')
    args = parser.parse_args()
    try:
        source = args.source.absolute()
        prefix, launcher = plan(source, args.homebrew_root)
        print(f'Hermes package source: {source}\nDedicated runtime: {prefix}\nNew launcher: {launcher}', flush=True)
        print('Installs a committed Hermes source snapshot and Python dependencies. The editable link stays inside the dedicated runtime; host login/state are excluded.', flush=True)
        if args.plan:
            return
        if sys.version_info < (3, 12):
            raise ValueError('Run this installer with Homebrew Python 3.14 (Python 3.12+ is required for safe archive extraction)')
        if sys.platform != 'darwin':
            raise ValueError('This installer is for native macOS only')
        install(source, args.homebrew_root, prefix, launcher)
        print('Installed. Your project must explicitly approve this Homebrew root in sandbox.runtime_roots.')
        print('Then run: runb doctor hermes\n          runb run hermes')
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Runtime installation stopped: {error}\n')


if __name__ == '__main__':
    main()
