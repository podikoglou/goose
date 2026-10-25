"""Unit test and verification check for Phase 4: Declarative Property Lowering (src/lower_prop.h).
Verifies:
1. ListPropTargets discovers all attached and standalone property targets.
2. GeneratePropHarness synthesizes correct proptest harnesses with:
   - Reverse-topological bound tightening (Tier 1 & 2)
   - Dynamic collection allocation and slice views
   - Campaign configurations from with(...)
   - Tier 3 assumption filtering (d.assume)
3. Target filtering (--target / prop_target).
4. The synthesized harness produces valid, compilable, and executable Goose code.
"""
import os
import sys
import tempfile
import subprocess
from pathlib import Path

FIB_SOURCE = """
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

COMPLEX_SOURCE = """
prop "compression roundtrip" for data where data.len > 0 with (iterations = 500, max_len = 128) {
    data.len > 0
}

prop "int slice" for (xs: const i64[:]) {
    xs.len >= 0
}

prop "linear constraint" for x, y where x in 1..=1000, y in 1..=1000, x + y < 1000 {
    (x + y) > x
}
"""

def check_prop_lowering(exe, base_dir=None):
    if base_dir is None:
        base_dir = tempfile.gettempdir()
    base = Path(base_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="prop-lower-", dir=base) as tmp:
        root = Path(tmp)
        fib_path = root / "fib_test.goose"
        fib_path.write_text(FIB_SOURCE, encoding="utf-8")

        # 1. Test target listing
        res = subprocess.run([str(exe), "check", str(fib_path), "--list-prop-targets"],
                             capture_output=True, text=True, cwd=root)
        if res.returncode != 0:
            raise RuntimeError(f"failed to list prop targets:\n{res.stderr}")
        targets = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
        expected_targets = ["fib::strictly monotonic", "fib"]
        if targets != expected_targets:
            raise RuntimeError(f"unexpected targets listed: {targets}, expected: {expected_targets}")

        # 2. Test harness generation for fib_test
        res = subprocess.run([str(exe), "check", str(fib_path), "--dump-prop-harness"],
                             capture_output=True, text=True, cwd=root)
        if res.returncode != 0:
            raise RuntimeError(f"failed to generate prop harness:\n{res.stderr}")
        harness = res.stdout

        # Verify key code generation properties in fib_test harness
        assert "import proptest;" in harness, "harness must import proptest"
        assert "import .fib_test;" in harness, "harness must import source stem"
        assert 'proptest::fuzz_target_name(c, "fib::strictly monotonic");' in harness, "must set fuzz target name"
        assert 'proptest::fuzz_target_name(c, "fib");' in harness, "must set fuzz target name"
        assert "d.gen_i64_range(2, 89);" in harness, "must generate reverse-topologically tightened bound [2, 89]"
        assert "d.gen_i64_range(i + 1, 90);" in harness, "must generate dependent bound [i + 1, 90]"
        assert "d.gen_i64_range(6, 90);" in harness, "must generate scalar bound [6, 90]"
        assert "(fib(i) < fib(j))" in harness, "must emit property expression"
        assert "(fib(i) > i)" in harness, "must emit property expression"
        assert "fn main() {" in harness, "must emit main runner"

        # 3. Check and run the generated fib harness
        fib_harness_file = root / "fib_harness.goose"
        fib_harness_file.write_text(harness, encoding="utf-8")

        res_check = subprocess.run([str(exe), "check", str(fib_harness_file)],
                                   capture_output=True, text=True, cwd=root)
        if res_check.returncode != 0:
            raise RuntimeError(f"synthesized fib harness failed typecheck:\n{res_check.stderr}")

        res_run = subprocess.run([str(exe), "run", str(fib_harness_file)],
                                 capture_output=True, text=True, cwd=root)
        if res_run.returncode != 0:
            raise RuntimeError(f"synthesized fib harness failed execution:\n{res_run.stderr}\n{res_run.stdout}")

        # 4. Test filtering with --target
        res_filter = subprocess.run([str(exe), "check", str(fib_path), "--dump-prop-harness",
                                     "--target", "fib::strictly_monotonic"],
                                    capture_output=True, text=True, cwd=root)
        if res_filter.returncode != 0:
            raise RuntimeError(f"filtering harness failed:\n{res_filter.stderr}")
        filtered_harness = res_filter.stdout
        assert "__prop_fib_strictly_monotonic" in filtered_harness, "must include requested target"
        assert "fn __prop_fib()" not in filtered_harness, "must not include filtered-out target"

        # 5. Test invalid filter returns failure
        res_invalid = subprocess.run([str(exe), "check", str(fib_path), "--dump-prop-harness",
                                      "--target", "non_existent_target"],
                                     capture_output=True, text=True, cwd=root)
        if res_invalid.returncode == 0:
            raise RuntimeError("filtering by non-existent target should fail with non-zero exit code")

        # 6. Test complex properties (slices, configs, Tier 3 assume)
        complex_path = root / "complex_test.goose"
        complex_path.write_text(COMPLEX_SOURCE, encoding="utf-8")

        res_complex = subprocess.run([str(exe), "check", str(complex_path), "--dump-prop-harness"],
                                     capture_output=True, text=True, cwd=root)
        if res_complex.returncode != 0:
            raise RuntimeError(f"failed to generate complex prop harness:\n{res_complex.stderr}")
        complex_harness = res_complex.stdout

        # Verify complex generation features
        assert "c = proptest::iterations(c, 500);" in complex_harness, "must apply iterations config"
        assert "c = proptest::max_len(c, 128);" in complex_harness, "must apply max_len config"
        assert "d.gen_bytes(1, 128);" in complex_harness, "must generate slice view with d.gen_bytes"
        assert "d.gen_array(0, 4096)" in complex_harness, "must generate array allocation with d.gen_array"
        assert "if !d.assume(((x + y) < 1000)) { return true; }" in complex_harness, "must generate Tier 3 d.assume check"

        # Check and run complex harness
        complex_harness_file = root / "complex_harness.goose"
        complex_harness_file.write_text(complex_harness, encoding="utf-8")

        res_ccheck = subprocess.run([str(exe), "check", str(complex_harness_file)],
                                    capture_output=True, text=True, cwd=root)
        if res_ccheck.returncode != 0:
            raise RuntimeError(f"synthesized complex harness failed typecheck:\n{res_ccheck.stderr}")

        res_crun = subprocess.run([str(exe), "run", str(complex_harness_file)],
                                  capture_output=True, text=True, cwd=root)
        if res_crun.returncode != 0:
            raise RuntimeError(f"synthesized complex harness failed execution:\n{res_crun.stderr}\n{res_crun.stdout}")

    print("Phase 4 declarative property lowering verification: ALL CHECKS PASSED")

if __name__ == "__main__":
    exe = sys.argv[1] if len(sys.argv) > 1 else "./build/goose"
    check_prop_lowering(Path(exe).resolve())
