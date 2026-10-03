import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scubatank import bootstrap


class BootstrapTests(unittest.TestCase):
    def test_verified_existing_runtime_does_not_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/"opa.exe";binary.write_bytes(b"synthetic binary")
            spec={"name":"opa_windows_amd64.exe","sha256":hashlib.sha256(binary.read_bytes()).hexdigest()}
            with patch.object(bootstrap,"runtime_spec",return_value=({"opa_version":"1.21.1"},spec)),patch.object(bootstrap,"urlopen",side_effect=AssertionError("network not allowed")):
                self.assertEqual(bootstrap.fetch_runtime(root),binary.resolve())

    def test_wrong_existing_binary_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"opa.exe").write_bytes(b"wrong bytes")
            spec={"name":"opa_windows_amd64.exe","sha256":"0"*64}
            with patch.object(bootstrap,"runtime_spec",return_value=({"opa_version":"1.21.1"},spec)),patch.object(bootstrap,"urlopen",side_effect=AssertionError("no automatic download")):
                with self.assertRaisesRegex(ValueError,"digest"):
                    bootstrap.fetch_runtime(root)


if __name__ == "__main__": unittest.main()
