# python_code_sandbox.py
from mcp.server.fastmcp import FastMCP
import ast
import json
import platform
import os
from .safe_executor import SafeExecutor
import tempfile
import logging

# Configure logger to file (to avoid interfering with MCP stdout)
log_file = os.path.join(tempfile.gettempdir(), "mcp_sandbox.log")
logging.basicConfig(
    filename=log_file,
    level=logging.CRITICAL, # Set to DEBUG if you need more detailed logging
    format="%(asctime)s - %(levelname)s - %(message)s"
)

mcp = FastMCP("Alx Python MCP Server")

# Determine platform
IS_UNIX = platform.system() != "Windows"
# Remove unused imports: resource, win32job, win32process

# ======================
# 🔍 SYNTAX CHECK FUNCTION
# ======================

@mcp.tool()
def check_syntax(code: str) -> str:
    """
    Safely checks Python code syntax without executing it.
    Uses the `ast` module (Abstract Syntax Tree) to parse the code.
    This check is the first validation step before executing code in the sandbox.
    It quickly identifies syntax errors such as missing colons,
    incorrect bracket placement, indentation issues, etc.

    :param code: A string containing Python code to be checked for syntax.
    :return: A JSON string with the check result.
             Example of a successful result: {"valid": true}
             Example of an error result: {
               "valid": false,
               "error": "invalid syntax",
               "line": 1,
               "offset": 9,
               "context": "if True"
             }
             Fields in case of error:
             - valid (bool): true if syntax is correct, false otherwise.
             - error (str, optional): Brief description of the error type.
             - line (int, optional): Line number where the error was detected (if applicable).
             - offset (int, optional): Character position in the line (1-indexed) where the error was detected (if applicable).
             - context (str, optional): The code fragment where the error occurred.
    """
    try:
        ast.parse(code)
        return json.dumps({"valid": True})
    
    except (SyntaxError, IndentationError) as e:
        context_lines = code.splitlines()
        error_line = ""
        if e.lineno and 0 < e.lineno <= len(context_lines):
            error_line = context_lines[e.lineno - 1]
        
        return json.dumps({
            "valid": False,
            "error": str(e).split('(', 1)[0].strip(),
            "line": e.lineno,
            "offset": e.offset,
            "context": error_line.strip() if error_line else ""
        })
    
    except Exception as e:
        return json.dumps({
            "valid": False,
            "error": f"Internal syntax checker error: {str(e)}",
            "line": None,
            "offset": None,
            "context": ""
        })

# ======================
# 🧪 MAIN TESTING TOOL
# ======================

@mcp.tool()
def test_code(
    code: str,
    timeout: float = 15.0,
    cpu_limit_sec: float = 10.0,      
    memory_limit_mb: int = 100       
) -> str:
    """
    Safely executes Python code with prior syntax validation.
    Uses check_syntax() to validate before execution.
    Code runs in an isolated sandbox with limits on time,
    memory, and CPU to prevent malicious behavior or excessive resource consumption.

    :param code: The code to execute.
    :param timeout: Overall real-time execution timeout in seconds.
                    If the code does not finish within this time, it will be terminated.
    :param cpu_limit_sec: CPU time limit for code execution (in seconds).
                          This is not the same as timeout! It represents the actual CPU time consumed.
                          On Unix: implemented via resource.setrlimit(RLIMIT_CPU).
                          On Windows: implemented via Job Objects (requires pywin32).
    :param memory_limit_mb: Virtual memory limit for the process (in MB).
                            On Unix: implemented via resource.setrlimit(RLIMIT_AS).
                            On Windows: implemented via Job Objects (requires pywin32).
    :return: A JSON string with results: stdout, stderr, exit_code, phase.
    """
    logging.info(f"🔄 Starting test_code with code: {repr(code[:50])}...") # Log start, truncated code

    # 1️⃣ PRELIMINARY SYNTAX CHECK
    syntax_result = json.loads(check_syntax(code))
    if not syntax_result["valid"]:
        logging.info("❌ Syntax error")
        syntax_result["phase"] = "syntax_check"
        return json.dumps(syntax_result)
    
    # 2️⃣ SECURITY CHECK
    violations = SecurityChecker.scan(code)
    if violations:
        logging.info(f"🔒 Security violations: {violations}")
        return json.dumps({
            "valid": False,
            "phase": "security_check",
            "violations": violations,
            "platform_warning": _get_platform_warning()
        })
    
    # 3️⃣ EXECUTION IN SANDBOX
    try:
        logging.info(f"⏳ Running SafeExecutor.run with limits: CPU={cpu_limit_sec}s, Mem={memory_limit_mb}MB...")
        result = SafeExecutor.run(
            code=code,
            timeout=timeout,
            cpu_limit_sec=cpu_limit_sec,    
            memory_limit_mb=memory_limit_mb 
        )
        logging.info(f"✅ SafeExecutor completed: exit_code={result.get('exit_code', 'N/A')}")
        result["phase"] = "execution"
        result["platform_warning"] = _get_platform_warning()
        logging.info("📤 Sending MCP response")
        return json.dumps(result)
    except Exception as e:
        logging.exception("💥 Error in test_code")
        return json.dumps({
            "valid": False,
            "phase": "execution",
            "error": f"Sandbox execution failed: {str(e)}"
        })

# ======================
# 🔐 HELPER CLASSES
# ======================

def _get_platform_warning() -> str:
    if IS_UNIX:
        return ""
    # Check if pywin32 is installed for better isolation on Windows
    try:
        import win32job # type: ignore
        return "Windows sandbox active with pywin32 support."
    except ImportError:
        return "Windows resource limits may be less effective (install pywin32 for full support via Job Objects)."

class SecurityChecker:
    """Checks code for dangerous constructs via AST analysis"""
    DANGEROUS_NAMES = {
        'open', '__import__', 'eval', 'exec', 'compile',
        'getattr', 'setattr', 'globals', 'locals', 'input',
        'help', 'dir', 'vars', 'breakpoint', 'memoryview'
    }
    
    DANGEROUS_MODULES = {
        'os', 'sys', 'subprocess', 'shutil', 'socket',
        'requests', 'urllib', 'pathlib', 'inspect', 'types',
        'ctypes', 'pickle', 'marshal', 'builtins', 'platform',
        'resource', 'signal' # Added resource because it can reset limits
    }

    @classmethod
    def scan(cls, code: str) -> list[str]:
        """Returns a list of security violations"""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return ["Syntax error (should have been caught earlier)"]
        
        visitor = cls._ASTVisitor()
        visitor.visit(tree)
        return visitor.violations

    class _ASTVisitor(ast.NodeVisitor):
        def __init__(self):
            self.violations = []
        
        def visit_Import(self, node: ast.Import):
            for alias in node.names:
                base_module = alias.name.split('.')[0]
                if base_module in SecurityChecker.DANGEROUS_MODULES:
                    self.violations.append(
                        f"Import of dangerous module: {base_module}"
                    )
            self.generic_visit(node)
        
        def visit_ImportFrom(self, node: ast.ImportFrom):
            if node.module:
                base_module = node.module.split('.')[0]
                if base_module in SecurityChecker.DANGEROUS_MODULES:
                    self.violations.append(
                        f"Import from dangerous module: {base_module}"
                    )
            self.generic_visit(node)
        
        def visit_Call(self, node: ast.Call):
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                if func_name in SecurityChecker.DANGEROUS_NAMES:
                    self.violations.append(
                        f"Call to dangerous function: {func_name}"
                    )
            self.generic_visit(node)


def main():
    mcp.run()

if __name__ == "__main__":
    main()