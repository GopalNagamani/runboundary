import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'create-freebuff-adapter.py'


class FreebuffAdapterTests(unittest.TestCase):
    def test_generator_names_only_minimal_files_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'state'
            source.mkdir()
            for name in ['credentials.json', 'device-key.json', 'freebuff', 'freebuff-metadata.json', 'settings.json', 'message-history.json']:
                path = source / name
                path.write_text('SYNTHETIC_PRIVATE_CONTENT')
                path.chmod(0o600)
            output = root / 'adapter.json'
            command = [sys.executable, str(SCRIPT), '--freebuff-home', str(source), '--output', str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('SYNTHETIC_PRIVATE_CONTENT', output.read_text())
            entries = json.loads(output.read_text())['files']
            self.assertEqual({Path(e['source']).name for e in entries}, {'credentials.json', 'device-key.json', 'freebuff', 'freebuff-metadata.json'})
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            previous = output.read_bytes()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(output.read_bytes(), previous)

    def test_generator_rejects_readable_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'credentials.json').write_text('SYNTHETIC_PRIVATE_CONTENT')
            (root / 'credentials.json').chmod(0o644)
            output = root / 'adapter.json'
            result = subprocess.run([sys.executable, str(SCRIPT), '--freebuff-home', str(root), '--output', str(output)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('SYNTHETIC_PRIVATE_CONTENT', result.stderr)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
