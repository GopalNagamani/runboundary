import importlib.util
from pathlib import Path
import tempfile
import unittest
import tarfile

spec = importlib.util.spec_from_file_location('hermes_installer', Path(__file__).resolve().parents[1] / 'install-hermes-runtime.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuntimeInstallerTests(unittest.TestCase):
    def test_plan_uses_dedicated_runtime_and_validates_source_and_root(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            with self.assertRaises(ValueError):
                module.plan(source, Path('/opt/homebrew'))
            (source / 'pyproject.toml').write_text('[project]\nname="synthetic-hermes"\n')
            with self.assertRaises(ValueError):
                module.plan(source, Path('/tmp/unsafe-root'))
            # No install or file mutation: these destination names must be fixed.
            prefix, launcher = module.plan(source, Path('/opt/homebrew'))
            self.assertEqual(prefix, Path('/opt/homebrew/opt/runboundary-hermes'))
            self.assertEqual(launcher, Path('/opt/homebrew/bin/hermes'))

    def test_archive_omits_secrets_and_rejects_escape_links(self):
        items = [tarfile.TarInfo('hermes_cli/main.py'), tarfile.TarInfo('.env'), tarfile.TarInfo('.envrc'), tarfile.TarInfo('auth.json')]
        self.assertEqual([m.name for m in module.validate_archive(items)], ['hermes_cli/main.py'])
        for name in ['../escape', '/absolute']:
            with self.assertRaises(ValueError):
                module.validate_archive([tarfile.TarInfo(name)])
        link = tarfile.TarInfo('link')
        link.type = tarfile.SYMTYPE
        link.linkname = '../../host'
        with self.assertRaises(ValueError):
            module.validate_archive([link])


if __name__ == '__main__':
    unittest.main()
