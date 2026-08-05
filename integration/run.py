import json
import os
from pathlib import Path
import subprocess
import sys


repository = Path(__file__).resolve().parents[1]
command = json.dumps(
    {
        "executable": sys.executable,
        "arguments": [str(repository / "tests" / "interop_engine.py")],
        "engine": "python",
    }
)
environment = os.environ.copy()
environment["YUUMI_INTEROP_COMMAND"] = command
subprocess.run(
    [
        "go",
        "test",
        "-tags=interop",
        "-run",
        "^TestGoEngineInterop$",
        "-count=1",
        "-timeout",
        "150s",
    ],
    cwd=repository.parent / "Yuumi",
    env=environment,
    check=True,
    timeout=180,
)


"""
The explicit adapter invokes the shared Go scenario suite with a real Python
engine fixture. Missing repositories or runtimes are errors, never skips.
"""
