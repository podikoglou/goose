// runtime-debug: proptest properties, generators, byte drivers and shrinking.
import std;
import proptest;

fn assert(cond: bool, msg: const u8[:] = "") {
    if !cond {
        if msg.len > 0 {
            print("assertion failed: ", msg);
        } else {
            print("assertion failed");
        }
        abort("test failed");
    }
}

fn test_driver_modes() {
    var d_prng = driver(42, 5);
    let u1 = d_prng.next_u64();
    let u2 = d_prng.next_u64();
    assert(u1 != u2, "prng driver produces distinct values");

    let raw: u8[4] = [0x12, 0x34, 0x56, 0x78];
    var d_buf = driver_from_bytes(raw, 5);
    assert(d_buf.has_bytes(), "buf has bytes");
    assert(d_buf.next_u8() == 0x12, "next_u8 matches");
    assert(d_buf.next_u8() == 0x34, "next_u8 matches");
    assert(d_buf.next_u16() == 0x7856, "next_u16 matches little endian");
    assert(!d_buf.has_bytes(), "buf exhausted");
    assert(d_buf.next_u8() == 0, "exhausted buf yields 0");

    var d_rec = recording_driver(1234, 5);
    let b = d_rec.next_u8();
    let w = d_rec.next_u32();
    let q = d_rec.next_u64();
    assert(d_rec.recorded.len == 13, "recorded bytes tracked correctly");
}

fn test_generators() {
    var d = driver(999, 5);
    let i = d.gen_i64_range(-50, 50);
    assert(i >= -50 && i <= 50, "i64 in range");

    let gi = d.gen_i64();
    assert(gi >= -9223372036854775807 - 1 && gi <= 9223372036854775807, "gen_i64 valid");

    let u = d.gen_u64_range(100, 200);
    assert(u >= 100 && u <= 200, "u64 in range");

    let gu = d.gen_u64();
    assert(gu >= 0, "gen_u64 valid");

    let flt = d.gen_f64_range(1.5, 9.5);
    assert(flt >= 1.5 && flt <= 9.5, "f64 in range");

    let gf = d.gen_f64();
    assert(gf == gf || gf != gf, "gen_f64 produces valid f64 (including nan)");

    let b = d.gen_bool();
    assert(b == true || b == false, "gen_bool valid");

    let b_alias = d.boolean();
    assert(b_alias == true || b_alias == false, "boolean alias valid");

    let s = d.gen_ascii_string(5, 10);
    assert(s.len >= 5 && s.len <= 10, "string len in range");

    var xs: i64[>..] = d.gen_array(3, 8) { dr => dr.gen_i64_range(0, 10) };
    assert(xs.len >= 3 && xs.len <= 8, "array len in range");

    let choices: i64[3] = [10, 20, 30];
    let pick = d.gen_one_of(choices);
    assert(pick == 10 || pick == 20 || pick == 30, "one_of picks valid choice");

    let nb = d.next_bool();
    assert(nb == true || nb == false, "next_bool valid");

    let ni8 = d.next_i8();
    let ni16 = d.next_i16();
    let ni32 = d.next_i32();
    let ni64 = d.next_i64();
    let nf32 = d.next_f32();
    let nf64 = d.next_f64();

    let ir = d.int_range(10, 20);
    assert(ir >= 10 && ir <= 20, "int_range in bounds");

    let ch = d.choose(choices);
    assert(ch == 10 || ch == 20 || ch == 30, "choose picks valid choice");

    let u8_arr = d.gen_u8_array(4, 12);
    assert(u8_arr.len >= 4 && u8_arr.len <= 12, "gen_u8_array in bounds");

    let weights: i64[3] = [0, 100, 0];
    let f_idx = d.frequency(weights);
    assert(f_idx == 1, "frequency selects only non-zero weight index");
}

fn test_properties() {
    // Commutativity of addition
    check()
        .seed(112233)
        .iterations(1000)
        .for_each() { d =>
            let a = d.gen_i64_range(-100000, 100000);
            let b = d.gen_i64_range(-100000, 100000);
            (a + b) == (b + a)
        };

    // Array sort idempotence
    check()
        .seed(445566)
        .iterations(200)
        .for_each() { d =>
            var xs: i64[>..] = d.gen_array(0, 30) { dr => dr.gen_i64_range(-1000, 1000) };
            xs.sort();
            var copy_xs: i64[>..] = copy(xs);
            copy_xs.sort();
            var eq = true;
            for idx in xs.len {
                if xs[idx] != copy_xs[idx] { eq = false; break; }
            }
            eq
        };
}

fn test_shrinking() {
    let res = check().seed(18248584007027029822).iterations(1).run() { d =>
        let a = d.gen_i64_range(0, 10000000);
        let b = d.gen_i64_range(0, 10000000);
        !(a >= 100 && b >= 200)
    };

    assert(!res.passed, "property must fail");
    assert(res.shrunk, "property result must be shrunk");
    assert(res.shrink_steps > 0, "shrink steps > 0");

    var d_min = driver_from_bytes(res.shrunk_bytes[..], 5);
    let a_min = d_min.gen_i64_range(0, 10000000);
    let b_min = d_min.gen_i64_range(0, 10000000);
    assert(a_min == 100, "a shrinks to exactly 100");
    assert(b_min == 200, "b shrinks to exactly 200");
}

fn test_doc_examples() {
    // Snippet from docs/stdlib.md:
    check().iterations(500).for_each() { d =>
        let a = d.int_range(-1000000, 1000000);
        let b = d.int_range(-1000000, 1000000);
        (a + b) == (b + a)
    };

    check().iterations(500).for_each() { d =>
        let name = d.ascii(1, 16);
        let score = d.int_range(0, 1000);
        let active = d.boolean();
        name.len >= 1 && score >= 0 && (active || !active)
    };
}

fn test_assume_filtering() {
    // 1. Filtering with assume: odd numbers are discarded
    var total_tested: i64 = 0;
    let res = check().iterations(200).run() { d =>
        let x = d.int_range(0, 100);
        if d.assume(x % 2 == 0) {
            assert(x % 2 == 0, "odd numbers must never reach this branch");
            total_tested += 1;
            true
        } else {
            false
        }
    };
    assert(res.passed, "assume property must pass");
    assert(res.total_iterations == 200, "all 200 iterations completed");
    assert(res.discarded_iterations > 0, "some odd numbers were discarded");
    assert(total_tested == 200, "tested exactly 200 valid cases");

    // 2. Statement assume: even when property expression is false on discarded input,
    // it is treated as a discard, not a failure.
    let res_stmt = check().iterations(100).run() { d =>
        let x = d.int_range(0, 100);
        d.assume(x % 2 == 0);
        x % 2 == 0
    };
    assert(res_stmt.passed, "statement assume must not fail even when property expression is false");
    assert(res_stmt.discarded_iterations > 0, "statement assume discarded cases");

    // 3. Discard cap: impossible assumption gives up safely without hanging
    let res_impossible = check().iterations(50).max_discards(100).run() { d =>
        d.assume(false);
        true
    };
    assert(!res_impossible.passed, "impossible assume must fail by hitting discard cap");
    assert(res_impossible.discarded_iterations >= 100, "discard count reached cap");

    // 4. filter alias
    let res_filter = check().iterations(50).run() { d =>
        let n = d.int_range(1, 10);
        d.filter(n > 5);
        n > 5
    };
    assert(res_filter.passed, "filter alias works as assume");
}

fn main() {
    test_driver_modes();
    test_generators();
    test_properties();
    test_shrinking();
    test_doc_examples();
    test_assume_filtering();
    print("proptest: all properties, generators, drivers and shrinking passed");
}
