# test_safe_executor.py

import unittest
import sys
import os

# Add current directory to path (if running directly)
sys.path.insert(0, os.path.dirname(__file__))

from safe_executor import SafeExecutor


class TestSafeExecutor(unittest.TestCase):

    def _run_and_report(self, test_name: str, code: str, timeout=5.0, cpu=1.0, mem=50):
        """Helper function to run and print result"""
        print(f"\n🧪 {test_name}")
        print(f"   Code: {repr(code)}")
        result = SafeExecutor.run(
            code=code,
            timeout=timeout,
            cpu_limit_sec=cpu,
            memory_limit_mb=mem
        )
        print(f"   → stdout: {repr(result['stdout'])}")
        print(f"   → stderr: {repr(result['stderr'])}")
        print(f"   → exit_code: {result['exit_code']}")
        return result

    def test_simple_expression(self):
        result = self._run_and_report(
            "Test simple calculation: 2 + 2",
            "print(2 + 2)"
        )
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"].strip(), "4")
        self.assertEqual(result["stderr"], "")

    def test_syntax_error_in_code(self):
        result = self._run_and_report(
            "Test syntax error",
            "print(2 +"
        )
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIn("SyntaxError", result["stderr"])

    def test_dangerous_function_blocked(self):
        result = self._run_and_report(
            "Test blocking of dangerous function: eval",
            "eval('2+2')"
        )
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIn("NameError", result["stderr"])
        self.assertIn("eval", result["stderr"])

    def test_import_blocked(self):
        result = self._run_and_report(
            "Test blocking of import: import os",
            "import os"
        )
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIn("ImportError", result["stderr"])

    def test_timeout(self):
        result = self._run_and_report(
            "Test timeout exceeded",
            "x = 0\nwhile True: x += 1",
            timeout=1.0,
            cpu=10.0,
            mem=50
        )
        self.assertEqual(result["exit_code"], 124)
        self.assertIn("timed out", result["stderr"])

    def test_no_output(self):
        result = self._run_and_report(
            "Test code with no output",
            "x = 42"
        )
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], "")
        self.assertEqual(result["stderr"], "")


if __name__ == "__main__":
    print("🚀 Running SafeExecutor tests")
    print("=" * 60)
    unittest.main(verbosity=2)