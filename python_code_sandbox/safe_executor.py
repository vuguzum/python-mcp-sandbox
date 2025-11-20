# safe_executor.py
import json
import subprocess
import sys
import textwrap
import platform
import os
from typing import Dict, Any
import tempfile
import logging

# Configure logger to file (to avoid interfering with MCP stdout)
log_file = os.path.join(tempfile.gettempdir(), "mcp_sandbox_executor.log")
logging.basicConfig(
    filename=log_file,
    level=logging.CRITICAL,  # Set to DEBUG if you need more detailed logging
    format="%(asctime)s - %(levelname)s - %(message)s"
)

IS_UNIX = platform.system() != "Windows"

class SafeExecutor:
    """Cross-platform code execution in isolation"""

    @staticmethod
    def run(
        code: str,
        timeout: float,
        cpu_limit_sec: float = 10.0,  # Added parameter
        memory_limit_mb: int = 100    # Added parameter
    ) -> Dict[str, Any]:
        sandbox_script = SafeExecutor._generate_sandbox_script(code)
        
        exe = sys.executable
        if exe.endswith("pythonw.exe"):
            exe = exe.replace("pythonw.exe", "python.exe")

        # Use a temporary file instead of -c
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(sandbox_script)
            script_path = f.name

        # Initialize variables that might not be defined in case of exception
        process = None
        job_handle = None
        exit_code = None

        try:
            # Copy environment but remove potentially dangerous PYTHONPATH
            clean_env = os.environ.copy()
            clean_env.pop("PYTHONPATH", None)
            clean_env["PYTHONUNBUFFERED"] = "1"

            # For Windows, copy critical variables if they exist
            if not IS_UNIX:
                for k in ("SystemRoot", "WINDIR", "TEMP", "TMP"):
                    if k in os.environ:
                        clean_env[k] = os.environ[k]

            # Prepare startupinfo for Windows (hide window)
            startupinfo = None
            creationflags = 0

            if IS_UNIX:
                # --- Unix: Prepare limits via preexec_fn ---
                # preexec_fn works only on Unix
                def preexec_set_limits():
                    import resource
                    if cpu_limit_sec > 0:
                        cpu_sec_int = int(cpu_limit_sec)
                        resource.setrlimit(resource.RLIMIT_CPU, (cpu_sec_int, cpu_sec_int))
                    if memory_limit_mb > 0:
                        mem_bytes = int(memory_limit_mb * 1024 * 1024)
                        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                    # resource.setrlimit(resource.RLIMIT_NOFILE, (0, 0)) # Optional
                    # resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)) # Optional

                process = subprocess.Popen(
                    [exe, script_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    env=clean_env,
                    text=True,
                    universal_newlines=True,
                    preexec_fn=preexec_set_limits # Set limits in child process
                )
            else: # Windows
                # --- Windows: Prepare Job Object ---
                try:
                    import win32job # type: ignore
                    import win32process # type: ignore
                    import win32con # type: ignore

                    # Create Job Object
                    job = win32job.CreateJobObject(None, "")

                    # Get limit information
                    extended_info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
                    extended_info['BasicLimitInformation']['LimitFlags'] = (
                        win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY | # Process memory limit
                        win32job.JOB_OBJECT_LIMIT_JOB_MEMORY |    # Job memory limit
                        win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | # Limit on number of active processes
                        win32job.JOB_OBJECT_LIMIT_PROCESS_TIME    # Process CPU time limit
                    )

                    # Set memory limit (in bytes)
                    if memory_limit_mb > 0:
                        mem_bytes = int(memory_limit_mb * 1024 * 1024)
                        extended_info['ProcessMemoryLimit'] = mem_bytes
                        extended_info['JobMemoryLimit'] = mem_bytes

                    # Set CPU time limit (in 100-nanosecond intervals)
                    if cpu_limit_sec > 0:
                        cpu_time_100ns = int(cpu_limit_sec * 10**7)
                        # Set as PerProcessUserTimeLimit
                        extended_info['BasicLimitInformation']['PerProcessUserTimeLimit'] = cpu_time_100ns
                        # Or PerJobUserTimeLimit for total time of all processes in Job
                        # extended_info['BasicLimitInformation']['PerJobUserTimeLimit'] = cpu_time_100ns

                    win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, extended_info)

                    # Prepare startupinfo
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE

                    # Launch process
                    process = subprocess.Popen(
                        [exe, script_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.DEVNULL,
                        env=clean_env,
                        text=True,
                        universal_newlines=True,
                        startupinfo=startupinfo,
                        creationflags=win32process.CREATE_SUSPENDED | subprocess.CREATE_NEW_PROCESS_GROUP # Create suspended
                    )

                    # Assign process to Job Object
                    win32job.AssignProcessToJobObject(job, process._handle) # Use _handle to access win32 handle

                    # Resume process execution
                    win32process.ResumeThread(process._handle)
                    win32process.CloseHandle(process._handle) # Close thread handle

                    # Save Job Object handle to close it later
                    job_handle = job

                except ImportError:
                    logging.error("pywin32 not available on Windows, resource limits cannot be set.")
                    # If pywin32 is not installed, run without Job Object
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                    process = subprocess.Popen(
                        [exe, script_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.DEVNULL,
                        env=clean_env,
                        text=True,
                        universal_newlines=True,
                        startupinfo=startupinfo
                    )
                except Exception as e:
                    logging.error(f"Failed to create/set Windows Job Object: {e}")
                    # In case of error working with Job Object, run without it
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                    process = subprocess.Popen(
                        [exe, script_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.DEVNULL,
                        env=clean_env,
                        text=True,
                        universal_newlines=True,
                        startupinfo=startupinfo
                    )

            stdout, stderr = process.communicate(timeout=timeout)
            exit_code = process.returncode
            
        except subprocess.TimeoutExpired:
            if process is not None:
                process.kill()
                try:
                    # Try to get output even after forced termination
                    stdout, stderr = process.communicate(timeout=1) # Small timeout to get remaining output
                except subprocess.TimeoutExpired:
                    stdout, stderr = "", "Process killed due to timeout."
            return {
                "stdout": "",
                "stderr": f"Execution timed out after {timeout} seconds",
                "exit_code": 124
            }
        finally:
            # Close Job Object (if created on Windows)
            if job_handle:
                try:
                    import win32job # type: ignore
                    win32job.CloseHandle(job_handle)
                except ImportError:
                    pass # pywin32 not installed, handle cannot be closed
                except Exception as e:
                    logging.warning(f"Could not close Job Object handle: {e}")

            # Delete temporary file
            try:
                os.unlink(script_path)
            except FileNotFoundError:
                # File already deleted (e.g. if process did not start)
                pass
            except Exception as e:
                # Ignore other errors during deletion, but can log
                logging.warning(f"Could not delete temporary script {script_path}: {e}")
            logging.info(f"✅ SafeExecutor completed: exit_code={exit_code}")

        # Try to parse result from sandbox
        try:
            return json.loads(stdout)
        except (json.JSONDecodeError, TypeError):
            # If parsing failed, return as error
            return {
                "stdout": stdout,
                "stderr": stderr or "Failed to parse sandbox output or sandbox did not return JSON.",
                "exit_code": exit_code if exit_code != 0 else 1
            }

    @staticmethod
    def _generate_sandbox_script(code: str) -> str:
        # Remove calls to generate limit code, as they are now set by external means
        dangerous_names = [
            '__import__', 'eval', 'exec', 'compile',
            'getattr', 'setattr', 'globals', 'locals',
            'help', 'dir', 'vars', 'breakpoint', 'memoryview'
        ]
        dangerous_modules = [
            'subprocess', 'shutil',
            'requests', 'urllib', 'pathlib', 'inspect', 'types',
            'ctypes', 'pickle', 'marshal', 'builtins',
            'resource', 'signal', # Remove resource so limits cannot be reset
            'getpass', 'os' # Remove os for greater security
        ]

        return textwrap.dedent(f'''
            import sys
            
            # EARLY DEBUGGER DISABLE
            sys.settrace(None)
            if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
                sys.settrace(None)
            
            # Remove debugpy traces if present
            for mod in list(sys.modules):
                if mod.startswith(('debugpy', 'pydevd', '_pydev')):
                    del sys.modules[mod]
            
            # Import necessary modules
            import json
            import io
            import builtins

            # Remove dangerous modules from sys.modules
            for mod in {dangerous_modules!r}:
                if mod in sys.modules:
                    del sys.modules[mod]

            # Create safe builtins dictionary
            SAFE_BUILTINS = {{
                name: getattr(builtins, name)
                for name in dir(builtins)
                if name not in {dangerous_names!r} and not name.startswith('_')
            }}

            # Disable import
            def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
                raise ImportError("All imports disabled in sandbox")

            safe_globals = {{
                '__builtins__': SAFE_BUILTINS,
                '__import__': restricted_import,
            }}

            # Disable open
            def disabled_open(*args, **kwargs):
                raise OSError("open() disabled in sandbox")
            safe_globals['open'] = disabled_open

            # Buffers for output capture
            stdout_buffer = io.StringIO()
            stderr_buffer = io.StringIO()

            # Redirect print
            def safe_print(*args, **kwargs):
                kwargs['file'] = stdout_buffer
                kwargs['flush'] = True
                print(*args, **kwargs)

            safe_globals['print'] = safe_print

            exit_code = 0
            try:
                # Execute user code
                exec({repr(code)}, safe_globals)
            except BaseException as e:
                stderr_buffer.write(f"{{type(e).__name__}}: {{e}}")
                exit_code = 1
            finally:
                result = {{
                    "stdout": stdout_buffer.getvalue(),
                    "stderr": stderr_buffer.getvalue(),
                    "exit_code": exit_code
                }}
                sys.stdout.write(json.dumps(result))
                sys.stdout.flush()

        ''')
