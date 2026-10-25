"""Test suite for Phase 5: goose test CLI subcommand and goose fuzz continuous property testing.
"""
import os
import re
import sys
import tempfile
import subprocess
from pathlib import Path

PASS_SOURCE = """
prop "strictly monotonic" for i, j where i in 2..=90, j in (i + 1)..=90 {
    fib(i) < fib(j)
}

prop for i where i in 6..=90 {
    fib(i) > i
}

fn fib(n: i64) -> i64 {
    var a: i64 = 0;
    var b: i64 = 1;
    for _ in n {
        let t = a + b;
        a = b;
        b = t;
    }
    a
}
"""

FAIL_SOURCE = """
prop "overflow failure" for i, j where i in 2..=95, j in (i + 1)..=95 {
    fib(i) < fib(j)
}

fn fib(n: i64) -> i64 {
    var a: i64 = 0;
    var b: i64 = 1;
    for _ in n {
        let t = a + b;
        a = b;
        b = t;
    }
    a
}
"""

EMPTY_SOURCE = """
fn add(a: i64, b: i64) -> i64 {
    a + b
}
"""

MIXED_FUZZ_SOURCE = """
fuzz fn fuzz_bytes(data: const u8[:]) {
    if data.len > 1000000 { abort("too long"); }
}

prop "prop target" for x where x in 0..=1000 {
    x >= 0
}
"""

def check_prop_cli(exe, base_dir=None):
    if base_dir is None:
        base_dir = tempfile.gettempdir()
    base = Path(base_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="prop-cli-", dir=base) as tmp:
        root = Path(tmp)

        # 1. goose test --help
        res = subprocess.run([str(exe), "test", "--help"],
                             capture_output=True, text=True, cwd=root)
        if res.returncode != 0:
            raise RuntimeError(f"goose test --help failed:\n{res.stderr}")
        assert "usage: goose test file.goose" in res.stdout, "help must include usage"
        assert "--target" in res.stdout, "help must document --target"
        assert "--list-targets" in res.stdout, "help must document --list-targets"
        assert "--seed" in res.stdout, "help must document --seed"
        assert "--replay" in res.stdout, "help must document --replay"
        assert "--timeout" in res.stdout, "help must document --timeout"
        assert "--max-len" in res.stdout, "help must document --max-len"

        # 2. File with no properties
        empty_path = root / "empty.goose"
        empty_path.write_text(EMPTY_SOURCE, encoding="utf-8")
        res_empty = subprocess.run([str(exe), "test", str(empty_path)],
                                   capture_output=True, text=True, cwd=root)
        if res_empty.returncode != 0:
            raise RuntimeError(f"goose test on file with no properties should exit 0, got {res_empty.returncode}")
        assert f"no property tests found in {empty_path}" in res_empty.stdout, "must report no property tests found"

        # 3. List targets
        pass_path = root / "pass.goose"
        pass_path.write_text(PASS_SOURCE, encoding="utf-8")
        res_list = subprocess.run([str(exe), "test", str(pass_path), "--list-targets"],
                                  capture_output=True, text=True, cwd=root)
        if res_list.returncode != 0:
            raise RuntimeError(f"goose test --list-targets failed:\n{res_list.stderr}")
        targets = [line.strip() for line in res_list.stdout.strip().splitlines() if line.strip()]
        expected = ["fib::strictly monotonic", "fib"]
        if targets != expected:
            raise RuntimeError(f"unexpected targets: {targets}, expected {expected}")

        # 4. Run all passing properties
        res_run = subprocess.run([str(exe), "test", str(pass_path)],
                                 capture_output=True, text=True, cwd=root)
        if res_run.returncode != 0:
            raise RuntimeError(f"goose test failed on passing properties:\n{res_run.stderr}\n{res_run.stdout}")
        assert "[PASS] fib::strictly monotonic" in res_run.stdout, "must report PASS for strictly monotonic"
        assert "[PASS] fib" in res_run.stdout, "must report PASS for fib"

        # 5. Run single target with --target
        res_target = subprocess.run([str(exe), "test", str(pass_path), "--target", "fib::strictly_monotonic"],
                                    capture_output=True, text=True, cwd=root)
        if res_target.returncode != 0:
            raise RuntimeError(f"goose test --target failed:\n{res_target.stderr}\n{res_target.stdout}")
        assert "[PASS] fib::strictly monotonic" in res_target.stdout, "must report PASS for strictly monotonic"
        assert "[PASS] fib\n" not in res_target.stdout, "must not run other properties"

        # 6. Non-existent target
        res_nonexistent = subprocess.run([str(exe), "test", str(pass_path), "--target", "missing_target"],
                                         capture_output=True, text=True, cwd=root)
        if res_nonexistent.returncode == 0:
            raise RuntimeError("goose test --target with non-existent target should exit non-zero")
        assert "not found" in res_nonexistent.stderr, "must report target not found"

        # 7. Failing property with counterexample discovery and reproduction instructions
        fail_path = root / "fail.goose"
        fail_path.write_text(FAIL_SOURCE, encoding="utf-8")
        res_fail = subprocess.run([str(exe), "test", str(fail_path)],
                                  capture_output=True, text=True, cwd=root)
        if res_fail.returncode == 0:
            raise RuntimeError("goose test should fail on integer overflow property")
        assert "======================== Test Failure ========================" in res_fail.stdout, "must print failure banner"
        assert "Target: fib::overflow failure" in res_fail.stdout, "must print target name"
        assert "Minimal failing bytes (hex):" in res_fail.stdout, "must print minimal bytes"
        assert "goose test" in res_fail.stdout, "reproduction command must recommend goose test"

        # Extract replay hex and seed
        seed_match = re.search(r"base seed:\s*(\d+)", res_fail.stdout)
        assert seed_match, "must print base seed"
        failed_seed = seed_match.group(1)

        # 8. Test replay with exact hex
        # The minimal bytes for fib(2) < fib(93) overflow are '00 21'
        res_replay = subprocess.run([str(exe), "test", str(fail_path), "--replay", "0021"],
                                    capture_output=True, text=True, cwd=root)
        if res_replay.returncode == 0:
            raise RuntimeError("replaying minimal counterexample should reproduce failure")
        assert "Replay failed" in res_replay.stdout, "must indicate replay failed"

        # 9. Test seed replay
        res_seed = subprocess.run([str(exe), "test", str(fail_path), "--seed", failed_seed],
                                  capture_output=True, text=True, cwd=root)
        if res_seed.returncode == 0:
            raise RuntimeError("replaying failed seed should reproduce failure")
        assert f"base seed: {failed_seed}" in res_seed.stdout, "must execute with specified seed"

        # 10. goose fuzz --list-targets discovers both fuzz fn and prop
        mixed_path = root / "mixed.goose"
        mixed_path.write_text(MIXED_FUZZ_SOURCE, encoding="utf-8")
        res_fuzz_list = subprocess.run([str(exe), "fuzz", str(mixed_path), "--list-targets"],
                                       capture_output=True, text=True, cwd=root)
        if res_fuzz_list.returncode != 0:
            raise RuntimeError(f"goose fuzz --list-targets failed:\n{res_fuzz_list.stderr}")
        assert "fuzz_bytes" in res_fuzz_list.stdout, "must list fuzz_bytes"
        assert "prop target" in res_fuzz_list.stdout, "must list prop target"

        # 11. goose fuzz targeting a prop declaration
        res_fuzz_prop = subprocess.run([str(exe), "fuzz", str(mixed_path),
                                        "--target", "prop target", "--timeout", "1"],
                                       capture_output=True, text=True, cwd=root)
        if res_fuzz_prop.returncode != 0:
            raise RuntimeError(f"goose fuzz on prop target failed:\n{res_fuzz_prop.stderr}\n{res_fuzz_prop.stdout}")
        assert "proptest [fuzz]:" in res_fuzz_prop.stdout, "must run continuous fuzzing on prop"

        # 12. End-to-end regression: stdlib_prop_fib.goose
        repo_test_dir = Path(__file__).resolve().parent
        fib_fixture = repo_test_dir / "stdlib" / "stdlib_prop_fib.goose"
        res_fib = subprocess.run([str(exe), "test", str(fib_fixture)],
                                 capture_output=True, text=True, cwd=root)
        if res_fib.returncode != 0:
            raise RuntimeError(f"goose test failed on {fib_fixture}:\n{res_fib.stderr}\n{res_fib.stdout}")
        assert "[PASS] fib::overtake index" in res_fib.stdout, "must pass overtake index"
        assert "[PASS] fib::strictly monotonic" in res_fib.stdout, "must pass strictly monotonic"

        # 13. End-to-end regression: stdlib_prop_slice.goose
        slice_fixture = repo_test_dir / "stdlib" / "stdlib_prop_slice.goose"
        res_slice = subprocess.run([str(exe), "test", str(slice_fixture)],
                                   capture_output=True, text=True, cwd=root)
        if res_slice.returncode != 0:
            raise RuntimeError(f"goose test failed on {slice_fixture}:\n{res_slice.stderr}\n{res_slice.stdout}")
        assert "[PASS] reverse::algebraic identity" in res_slice.stdout, "must pass algebraic identity"
        assert "[PASS] reverse::bounded slice" in res_slice.stdout, "must pass bounded slice"

        # 14. End-to-end regression: stdlib_prop_stacking.goose
        stacking_fixture = repo_test_dir / "stdlib" / "stdlib_prop_stacking.goose"
        res_stack = subprocess.run([str(exe), "test", str(stacking_fixture)],
                                   capture_output=True, text=True, cwd=root)
        if res_stack.returncode != 0:
            raise RuntimeError(f"goose test failed on {stacking_fixture}:\n{res_stack.stderr}\n{res_stack.stdout}")
        assert "[PASS] sort::idempotent" in res_stack.stdout, "must pass sort::idempotent"
        assert "[PASS] sort::preserves length" in res_stack.stdout, "must pass sort::preserves length"

        # 15. End-to-end regression: stdlib_prop_overflow.goose
        overflow_fixture = repo_test_dir / "stdlib" / "stdlib_prop_overflow.goose"
        res_of = subprocess.run([str(exe), "test", str(overflow_fixture)],
                                capture_output=True, text=True, cwd=root)
        if res_of.returncode == 0:
            raise RuntimeError(f"goose test on {overflow_fixture} should fail due to integer overflow")
        assert "======================== Test Failure ========================" in res_of.stdout
        assert "Target: fib::strictly monotonic" in res_of.stdout

        # Extract minimal failing bytes hex
        lines = res_of.stdout.splitlines()
        hex_bytes = []
        in_hex = False
        for line in lines:
            if "Minimal failing bytes" in line:
                in_hex = True
                continue
            if in_hex:
                if "Reproduction" in line or line.startswith("==="):
                    break
                m = re.match(r"^[0-9a-fA-F]+:\s+((?:[0-9a-fA-F]{2}\s*)+)", line)
                if m:
                    hex_bytes.append(m.group(1).replace(" ", ""))
        replay_hex = "".join(hex_bytes)
        assert replay_hex, "must extract minimal failing bytes hex"

        # Replay overflow counterexample
        res_rep = subprocess.run([str(exe), "test", str(overflow_fixture), "--replay", replay_hex],
                                 capture_output=True, text=True, cwd=root)
        if res_rep.returncode == 0:
            raise RuntimeError(f"replaying overflow counterexample {replay_hex} should fail")
        assert "Replay failed" in res_rep.stdout, "replay must report Replay failed"

    print("Phase 5 & 6 declarative property verification CLI verification: ALL CHECKS PASSED")

if __name__ == "__main__":
    exe = sys.argv[1] if len(sys.argv) > 1 else "./build/goose"
    check_prop_cli(Path(exe).resolve())
