import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def run_cli(self,*args):
        return subprocess.run([sys.executable,"-m","scubatank",*map(str,args)],cwd=ROOT,capture_output=True,text=True,timeout=60)

    def test_plan_is_offline_and_only_six_rules_implemented(self):
        result=self.run_cli("plan")
        self.assertEqual(result.returncode,0,result.stderr)
        plan=json.loads(result.stdout)
        self.assertEqual(len(plan["implemented_rules"]),6)
        self.assertFalse(plan["network_access"])

    def test_demo_writes_complete_readable_deliverables(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"demo with spaces ; $ literal"
            result=self.run_cli("demo","--output-dir",out)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue((out/"bundle.json").is_file())
            self.assertTrue((out/"assessment.json").is_file())
            for name in ("report.html","report.json","report.md","findings.csv"):
                self.assertTrue((out/"reports"/name).is_file(),name)
            data=json.loads((out/"assessment.json").read_text())
            self.assertEqual(data["counts"]["Fail"],6)

    def test_bad_manifest_returns_nonzero_without_traceback(self):
        result=self.run_cli("import","--manifest","missing.json","--output",".build/should-not-exist.json")
        self.assertEqual(result.returncode,2)
        self.assertNotIn("Traceback",result.stderr)


if __name__=="__main__":unittest.main()
