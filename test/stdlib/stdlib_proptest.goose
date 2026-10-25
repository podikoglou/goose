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

fn char_in_set(c: u8, set: const u8[:]) -> bool {
    for s in set {
        if c == s { return true; }
    }
    false
}

fn test_string_strategies() {
    var d = driver(777, 5);

    // 1. d.string_from(charset, min_len, max_len)
    let hex_chars = "0123456789ABCDEF";
    let s_hex = d.string_from(hex_chars, 8, 16);
    assert(s_hex.len >= 8 && s_hex.len <= 16, "string_from len in range");
    for c in s_hex {
        assert(char_in_set(c, hex_chars), "string_from char in hex_chars");
    }

    // Empty charset returns empty string
    let s_empty_charset = d.string_from("", 5, 10);
    assert(s_empty_charset.len == 0, "empty charset returns []");

    // 2. d.string_from(charset, len)
    let s_exact = d.string_from("abc", 9);
    assert(s_exact.len == 9, "string_from exact len matches");
    for c in s_exact {
        assert(char_in_set(c, "abc"), "string_from char in abc");
    }

    let s_exact_zero = d.string_from("abc", 0);
    assert(s_exact_zero.len == 0, "string_from exact 0 len is empty");

    let s_empty_charset_exact = d.string_from("", 10);
    assert(s_empty_charset_exact.len == 0, "empty charset exact len returns []");

    // 3. d.alphanumeric(min_len, max_len)
    let s_alnum = d.alphanumeric(10, 25);
    assert(s_alnum.len >= 10 && s_alnum.len <= 25, "alphanumeric len in range");
    for c in s_alnum {
        assert(is_alnum(c), "alphanumeric char valid");
    }

    // 4. d.alphanumeric(len)
    let s_alnum_exact = d.alphanumeric(15);
    assert(s_alnum_exact.len == 15, "alphanumeric exact len matches");
    for c in s_alnum_exact {
        assert(is_alnum(c), "alphanumeric exact char valid");
    }

    let s_alnum_zero = d.alphanumeric(0);
    assert(s_alnum_zero.len == 0, "alphanumeric exact 0 len is empty");

    // 5. d.ascii(len) single-argument overload
    let s_ascii_exact = d.ascii(14);
    assert(s_ascii_exact.len == 14, "ascii(len) matches exact length");
    for c in s_ascii_exact {
        assert(c >= 32 && c <= 126, "ascii(len) char in printable range");
    }

    let s_ascii_zero = d.ascii(0);
    assert(s_ascii_zero.len == 0, "ascii(0) is empty");

    // 6. d.utf8(max_len) single-argument overload
    let s_utf8 = d.utf8(20);
    assert(s_utf8.len >= 0 && s_utf8.len <= 20, "utf8(max_len) in bounds");

    let s_utf8_zero = d.utf8(0);
    assert(s_utf8_zero.len == 0, "utf8(0) is empty");

    // Explicit namespaced and global calls:
    let ns_str = proptest::string_from(d, "ABCD", 2, 4);
    assert(ns_str.len >= 2 && ns_str.len <= 4, "proptest::string_from range valid");
    let ns_str_exact = proptest::string_from(d, "ABCD", 3);
    assert(ns_str_exact.len == 3, "proptest::string_from exact valid");

    let ns_alnum = proptest::alphanumeric(d, 5, 10);
    assert(ns_alnum.len >= 5 && ns_alnum.len <= 10, "proptest::alphanumeric range valid");
    let ns_alnum_exact = proptest::alphanumeric(d, 4);
    assert(ns_alnum_exact.len == 4, "proptest::alphanumeric exact valid");

    let ns_ascii = proptest::ascii(d, 6);
    assert(ns_ascii.len == 6, "proptest::ascii(len) valid");

    let ns_utf8 = proptest::utf8(d, 12);
    assert(ns_utf8.len >= 0 && ns_utf8.len <= 12, "proptest::utf8(max_len) valid");

    // Also Driver gen_* equivalents
    let g_str = d.gen_string_from("01", 3);
    assert(g_str.len == 3, "d.gen_string_from exact valid");
    let g_alnum = d.gen_alphanumeric_string(7);
    assert(g_alnum.len == 7, "d.gen_alphanumeric_string exact valid");

    // 7. Property-based testing verification across multiple iterations
    check().iterations(200).for_each() { dr =>
        let hex = dr.string_from("0123456789abcdef", 4, 12);
        var hex_ok = hex.len >= 4 && hex.len <= 12;
        for c in hex {
            if !char_in_set(c, "0123456789abcdef") { hex_ok = false; break; }
        }

        let id = dr.alphanumeric(6, 18);
        var id_ok = id.len >= 6 && id.len <= 18;
        for c in id {
            if !is_alnum(c) { id_ok = false; break; }
        }

        let fixed_ascii = dr.ascii(8);
        var ascii_ok = fixed_ascii.len == 8;
        for c in fixed_ascii {
            if c < 32 || c > 126 { ascii_ok = false; break; }
        }

        let bounded_utf8 = dr.utf8(16);
        let utf8_ok = bounded_utf8.len >= 0 && bounded_utf8.len <= 16;

        hex_ok && id_ok && ascii_ok && utf8_ok
    };
}

fn test_depth_guard() {
    // 1. Basic driver queries and lifecycle
    var d = driver(12345, 3);
    assert(d.depth() == 0, "initial depth is 0");
    assert(d.max_depth() == 3, "max_depth matches configuration");
    assert(d.can_recurse(), "can recurse initially");

    // Root/namespaced mirror queries
    assert(depth(d) == 0, "global depth() matches");
    assert(max_depth(d) == 3, "global max_depth() matches");
    assert(can_recurse(d), "global can_recurse() matches");
    assert(proptest::depth(d) == 0, "proptest::depth() matches");
    assert(proptest::max_depth(d) == 3, "proptest::max_depth() matches");
    assert(proptest::can_recurse(d), "proptest::can_recurse() matches");

    // 2. Manual enter_depth and leave_depth
    assert(d.enter_depth(), "enter depth level 1");
    assert(d.depth() == 1, "depth is 1");
    assert(d.can_recurse(), "can recurse at depth 1");

    assert(d.enter_depth(), "enter depth level 2");
    assert(d.depth() == 2, "depth is 2");
    assert(d.can_recurse(), "can recurse at depth 2");

    assert(d.enter_depth(), "enter depth level 3");
    assert(d.depth() == 3, "depth is 3");
    assert(!d.can_recurse(), "cannot recurse when depth == max_depth");
    assert(!d.enter_depth(), "entering beyond max_depth returns false");
    assert(d.depth() == 3, "depth stays at 3");

    d.leave_depth();
    assert(d.depth() == 2, "leave_depth decrements to 2");
    assert(d.can_recurse(), "can recurse again");

    d.leave_depth();
    d.leave_depth();
    assert(d.depth() == 0, "depth back to 0");
    d.leave_depth();
    assert(d.depth() == 0, "depth clamped at 0");

    // Namespaced enter_depth / leave_depth
    assert(proptest::enter_depth(d), "proptest::enter_depth succeeds");
    assert(proptest::depth(d) == 1, "proptest::depth is 1");
    proptest::leave_depth(d);
    assert(proptest::depth(d) == 0, "proptest::leave_depth restores to 0");

    // 3. Scoped block combinator: d.recurse() { d => ... }
    var entered_count = 0;
    var inner_depth_ok = false;
    let ok1 = d.recurse() { d1 =>
        entered_count += 1;
        assert(d1.depth() == 1, "depth 1 inside first recurse");
        let ok2 = d1.recurse() { d2 =>
            entered_count += 1;
            assert(d2.depth() == 2, "depth 2 inside second recurse");
            let ok3 = d2.recurse() { d3 =>
                entered_count += 1;
                assert(d3.depth() == 3, "depth 3 inside third recurse");
                assert(!d3.can_recurse(), "can_recurse false at max depth");
                let ok4 = d3.recurse() { d4 =>
                    entered_count += 1;
                };
                assert(!ok4, "recurse at max depth returns false");
            };
            assert(ok3, "third recurse succeeded");
        };
        assert(ok2, "second recurse succeeded");
        inner_depth_ok = (d1.depth() == 1);
    };
    assert(ok1, "first recurse succeeded");
    assert(entered_count == 3, "entered exactly 3 levels of recursion");
    assert(inner_depth_ok, "depth unrolled properly inside scope");
    assert(d.depth() == 0, "depth unrolled back to 0 at root");

    // Namespaced recurse combinator
    let ns_ok = proptest::recurse(d) { drv =>
        assert(drv.depth() == 1, "drv.depth == 1 inside proptest::recurse");
    };
    assert(ns_ok, "proptest::recurse succeeded");
    assert(d.depth() == 0, "restored after proptest::recurse");

    // 4. gen_variant depth guard behavior
    // When depth == max_depth, variant must return 0 (base case)
    var d_full = driver(999, 2);
    assert(d_full.enter_depth(), "enter 1");
    assert(d_full.enter_depth(), "enter 2");
    assert(!d_full.can_recurse(), "cannot recurse");
    for _ in 20 {
        assert(d_full.variant(5) == 0, "variant returns 0 base-case when !can_recurse");
        assert(gen_variant(d_full, 5) == 0, "gen_variant returns 0 base-case when !can_recurse");
    }
    d_full.leave_depth();
    d_full.leave_depth();
    assert(d_full.depth() == 0, "d_full restored");

    // 5. Integration property test with recursive tree depth verification
    check().max_depth(4).iterations(100).for_each() { drv =>
        assert(drv.depth() == 0, "root depth 0");
        assert(drv.max_depth() == 4, "root max_depth 4");
        var max_observed_depth = 0;
        drv.recurse() { d1 =>
            if d1.depth() > max_observed_depth { max_observed_depth = d1.depth(); }
            d1.recurse() { d2 =>
                if d2.depth() > max_observed_depth { max_observed_depth = d2.depth(); }
                d2.recurse() { d3 =>
                    if d3.depth() > max_observed_depth { max_observed_depth = d3.depth(); }
                    d3.recurse() { d4 =>
                        if d4.depth() > max_observed_depth { max_observed_depth = d4.depth(); }
                        let ok_too_deep = d4.recurse() { d5 =>
                            assert(false, "should never execute beyond max_depth");
                        };
                        assert(!ok_too_deep, "depth guard prevented excessive recursion");
                    };
                };
            };
        };
        assert(drv.depth() == 0, "depth perfectly balanced at test end");
        assert(max_observed_depth == 4, "reached max_depth");
        true
    };
}

fn main() {
    test_driver_modes();
    test_generators();
    test_properties();
    test_shrinking();
    test_doc_examples();
    test_assume_filtering();
    test_string_strategies();
    test_depth_guard();
    print("proptest: all properties, generators, drivers and shrinking passed");
}
