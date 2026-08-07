# Continuous integration

Workflow: `.github/workflows/ci.yml`.

- Triggers: pushes and pull requests for `main` and `dev`, plus manual dispatch.
- Platforms: `windows-latest`, `ubuntu-latest`, and `macos-latest`.
- Toolchains: latest stable Python 3 and latest stable Go.
- Gates: wheel build, dependency consistency, 25 engine cases, and real Go interop.
- Spec pin: `45729f1075ec5afcd9fd811db944385d6672eec3`; changing it requires an explicit
  reviewed workflow edit.
- Cache: disabled until run timings demonstrate a useful target.
- Timeout: 10 minutes for spec validation and 25 minutes per platform cell.
- Artifacts: wheel, per-case report, logs, cleanup diagnostics, toolchain
  versions, and repository commits, retained for 14 days.

Local equivalent from the directory containing all repositories:

```powershell
python -m pip wheel --no-deps --wheel-dir artifacts/package ./yuumi-py
python yuumi-spec/conformance/harness.py --repositories-root . --spec-sha 45729f1075ec5afcd9fd811db944385d6672eec3 --platform windows --sdk python --stage all --output-dir artifacts/python
```

No test token is written to logs. The private fixture and testkit are excluded
from the wheel, and endpoint reuse is checked after success and injected failure.
