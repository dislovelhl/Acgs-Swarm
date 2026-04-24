# SWE-Bench Local Dockerless Smoke

Date: 2026-04-23

## Summary

One SWE-Bench-shaped instance was evaluated end-to-end with the repository's Docker-less local harness path:

- Instance: `local__demo-0001`
- Evaluation mode: `local_dockerless`
- Result: PASS
- Harness stage: `done`
- Patch applied: `true`
- Resolved: `true`
- FAIL_TO_PASS: `1/1`
- PASS_TO_PASS: `1/1`
- Harness runtime: `1.826339353021467s`
- Command wall time: `2s`

The run used a synthetic local Git fixture because the sandbox did not have an official local SWE-Bench JSONL fixture and the normal script path could not import the package runtime without missing environment dependencies.

## Command

Smallest viable repository runner checked:

```bash
python scripts/run_swe_bench_lite.py --help
```

That command was not usable in this checkout because top-level package import side effects exposed Bittensor argparse options instead of the script's own SWE-Bench options.

The guarded swarm runner was then checked:

```bash
python scripts/run_swe_bench_swarm_lite.py --help
```

It exposed the expected local validation options, but executing it against one local JSONL instance failed before harness execution because runtime dependencies were missing:

```bash
HOME=/tmp/c5-swebench-home PATH=/tmp/c5-bin:$PATH \
  python scripts/run_swe_bench_swarm_lite.py \
  --jsonl /tmp/c5-swebench/one_instance.jsonl \
  --limit 1 \
  --backend codex \
  --agents 1 \
  --mode in-memory \
  --agent-timeout 30 \
  --harness-timeout 120 \
  --output /tmp/c5-swebench/result.json \
  --verbose
```

Observed blockers:

- Without extra `PYTHONPATH`: `ModuleNotFoundError: No module named 'acgs_lite'`.
- With `PYTHONPATH=/home/martin/Downloads/ACGS/packages/acgs-lite/src`: `ModuleNotFoundError: No module named 'pydantic'`.

Final local Docker-less harness command used:

```bash
python - <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

module_path = Path("src/constitutional_swarm/swe_bench/local_harness.py").resolve()
spec = importlib.util.spec_from_file_location("local_harness_direct", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
assert spec.loader is not None
spec.loader.exec_module(module)

instance = json.loads(
    Path("/tmp/c5-swebench/one_instance.jsonl")
    .read_text(encoding="utf-8")
    .splitlines()[0]
)
harness = module.LocalSWEBenchHarness(
    work_dir=Path("/tmp/c5-swebench-home/.cache/constitutional_swarm/swe_bench"),
    timeout_s=120,
)
result = harness.evaluate(instance, instance["patch"])
print(
    json.dumps(
        {
            "evaluation_mode": "local_dockerless",
            "instance_id": result.instance_id,
            "applied": result.applied,
            "resolved": result.resolved,
            "fail_to_pass_passed": result.fail_to_pass_passed,
            "fail_to_pass_failed": result.fail_to_pass_failed,
            "pass_to_pass_passed": result.pass_to_pass_passed,
            "pass_to_pass_failed": result.pass_to_pass_failed,
            "stage": result.stage,
            "error": result.error,
            "duration_s": result.duration_s,
            "metadata": result.metadata,
            "log_tail": result.log_tail,
        },
        indent=2,
    )
)
PY
```

## Output

```json
{
  "evaluation_mode": "local_dockerless",
  "instance_id": "local__demo-0001",
  "applied": true,
  "resolved": true,
  "fail_to_pass_passed": 1,
  "fail_to_pass_failed": 0,
  "pass_to_pass_passed": 1,
  "pass_to_pass_failed": 0,
  "stage": "done",
  "error": null,
  "duration_s": 1.826339353021467,
  "metadata": {
    "test_runner": "pytest"
  },
  "log_tail": ""
}
```

## Instance

```json
{
  "instance_id": "local__demo-0001",
  "repo": "local/demo",
  "base_commit": "ec52d33cb0cd17213822c3bbe908108c5a6b19f4",
  "FAIL_TO_PASS": ["tests/test_calc.py::test_add_regression"],
  "PASS_TO_PASS": ["tests/test_calc.py::test_subtract_still_works"]
}
```

The local fixture repository was preloaded at:

```text
/tmp/c5-swebench-home/.cache/constitutional_swarm/swe_bench/repos/local_demo
```

This minimally mocked the GitHub clone step that would otherwise require network egress. The harness still performed a fresh shared clone into its worktree, checked out `base_commit`, applied the patch, selected the pytest runner, and ran both listed tests.

## Caveats Vs Official Leaderboard

1. This is a synthetic local fixture, not an official SWE-Bench Lite leaderboard instance.
2. The run used `local_dockerless`; official SWE-Bench scoring uses per-instance Docker images with pinned environments.
3. Tests ran under the host Python interpreter and host pytest, so interpreter, package, and system-library differences can change outcomes.
4. Environment isolation was disabled; the target repo was not installed into a per-instance virtualenv.
5. GitHub clone/network access was mocked by preloading the harness repo cache.
6. Patch generation was bypassed with the known fixture patch; this validates the local harness path, not model solve quality.
7. The current `HarnessResult.metadata` did not include the documented `evaluation_mode` key; the mode is recorded here from the invoked harness path.

## Reproduce

From `/home/martin/Downloads/ACGS/packages/constitutional_swarm`:

```bash
python - <<'PY'
import json
import os
import shutil
import subprocess
from pathlib import Path

base = Path("/tmp/c5-swebench")
home = Path("/tmp/c5-swebench-home")
for path in (base, home):
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)

repo = home / ".cache" / "constitutional_swarm" / "swe_bench" / "repos" / "local_demo"
(repo / "demo_pkg").mkdir(parents=True)
(repo / "tests").mkdir(parents=True)
(repo / "demo_pkg" / "__init__.py").write_text("", encoding="utf-8")
(repo / "demo_pkg" / "calc.py").write_text(
    "def add(a, b):\n    return a - b\n\n\ndef subtract(a, b):\n    return a - b\n",
    encoding="utf-8",
)
(repo / "tests" / "test_calc.py").write_text(
    "from demo_pkg.calc import add, subtract\n\n"
    "def test_add_regression():\n    assert add(2, 3) == 5\n\n"
    "def test_subtract_still_works():\n    assert subtract(5, 2) == 3\n",
    encoding="utf-8",
)
subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
subprocess.run(["git", "config", "user.email", "c5@example.invalid"], cwd=repo, check=True)
subprocess.run(["git", "config", "user.name", "C5 Fixture"], cwd=repo, check=True)
subprocess.run(["git", "add", "demo_pkg", "tests"], cwd=repo, check=True)
subprocess.run(
    ["git", "commit", "-m", "Create local dockerless SWE-bench fixture"],
    cwd=repo,
    check=True,
    capture_output=True,
    text=True,
)
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
patch = """--- a/demo_pkg/calc.py
+++ b/demo_pkg/calc.py
@@ -1,5 +1,5 @@
 def add(a, b):
-    return a - b
+    return a + b


 def subtract(a, b):
"""
instance = {
    "instance_id": "local__demo-0001",
    "repo": "local/demo",
    "base_commit": commit,
    "problem_statement": "The add helper subtracts its second operand.",
    "FAIL_TO_PASS": ["tests/test_calc.py::test_add_regression"],
    "PASS_TO_PASS": ["tests/test_calc.py::test_subtract_still_works"],
    "patch": patch.replace("++++ b/", "+++ b/"),
}
(base / "one_instance.jsonl").write_text(json.dumps(instance) + "\n", encoding="utf-8")
print(base / "one_instance.jsonl")
PY

python - <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

module_path = Path("src/constitutional_swarm/swe_bench/local_harness.py").resolve()
spec = importlib.util.spec_from_file_location("local_harness_direct", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
assert spec.loader is not None
spec.loader.exec_module(module)

instance = json.loads(
    Path("/tmp/c5-swebench/one_instance.jsonl")
    .read_text(encoding="utf-8")
    .splitlines()[0]
)
harness = module.LocalSWEBenchHarness(
    work_dir=Path("/tmp/c5-swebench-home/.cache/constitutional_swarm/swe_bench"),
    timeout_s=120,
)
result = harness.evaluate(instance, instance["patch"])
print(result)
raise SystemExit(0 if result.resolved else 1)
PY
```
