import os
import subprocess
import unittest
from pathlib import Path


class PixiewpsCliParamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidates = [Path("build/pixiewps-1.2"), Path("build/pixiewps"), Path("pixiewps")]
        for candidate in candidates:
            if candidate.exists() and os.access(candidate, os.X_OK):
                cls.binary = str(candidate)
                return
        raise unittest.SkipTest("pixiewps binary was not found; build it first")

    def run_cli(self, *args):
        return subprocess.run(
            [self.binary, *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_cli_accepts(self, *args):
        result = self.run_cli(*args)
        combined = result.stdout + result.stderr
        self.assertTrue(
            result.returncode != 0 or "Pixiewps" in combined or "Usage" in combined,
            msg=f"Unexpected CLI behavior for args {args}: {combined}",
        )
        self.assertNotIn("unrecognized option", combined.lower())

    def test_help_and_version_flags(self):
        self.assert_cli_accepts("-h")
        self.assert_cli_accepts("--help")
        self.assert_cli_accepts("-V")
        self.assert_cli_accepts("--version")

    def test_required_and_compatibility_flags(self):
        cases = [
            ("-e", "abc", "--help"),
            ("--pke", "abc", "--help"),
            ("-r", "abc", "--help"),
            ("-s", "abc", "--help"),
            ("-z", "abc", "--help"),
            ("-a", "abc", "--help"),
            ("-n", "abc", "--help"),
            ("-m", "abc", "--help"),
            ("-b", "abc", "--help"),
            ("-o", "out.bin", "--help"),
            ("-v", "--help"),
            ("--verbosity", "2", "--help"),
            ("-j", "2", "--help"),
            ("--jobs", "2", "--help"),
            ("-S", "--help"),
            ("-f", "--help"),
            ("-l", "--help"),
            ("-i", "wlan0", "--help"),
            ("--interface", "wlan0", "--help"),
            ("--bssid", "AA:BB:CC:DD:EE:FF", "--help"),
            ("--hybrid", "--help"),
            ("--pixie-dust", "--help"),
            ("-K", "--help"),
            ("-Z", "--help"),
            ("--static-pke", "--help"),
            ("--brute-force", "--help"),
            ("--detect", "--help"),
            ("--retry", "3", "--help"),
            ("-g", "10", "--help"),
            ("--max-attempts", "10", "--help"),
            ("--mode", "3", "--help"),
            ("--start", "01/2024", "--help"),
            ("--end", "02/2024", "--help"),
            ("--cstart", "100", "--help"),
            ("--cend", "200", "--help"),
            ("-5", "abc", "--help"),
            ("-7", "abc", "--help"),
        ]

        for case in cases:
            with self.subTest(args=case):
                self.assert_cli_accepts(*case)

    def test_combined_compatibility_flags(self):
        self.assert_cli_accepts(
            "--pixie-dust",
            "--detect",
            "--retry",
            "3",
            "--max-attempts",
            "10",
            "--help",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
