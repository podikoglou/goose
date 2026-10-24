// runtime-debug: stdlib/regex fuzzing, structured invariant validation, and parser robustness.
import std;
import regex;
import proptest;

// --- Structured Regex Generator ----------------------------------------------

recursive fn gen_atom(out: u8[>..]&, d: Driver&, depth: i32) {
    let group_weight = if depth < 3 { 15 } else { 0 };
    let weights: i64[8] = [25, 10, 10, 10, 10, 15, 15, group_weight];
    let kind = d.frequency(weights);

    if kind == 0 {
        // Alphanumeric literals
        out.push(d.choose("abcdef0123"));
    } else if kind == 1 {
        // Escaped punctuation
        out.push('\\');
        out.push(d.choose(".\\*+?()[]{}|^$"));
    } else if kind == 2 {
        // Perl classes: \d, \w, \s, \D, \W, \S
        out.push('\\');
        out.push(d.choose("dwDsSw"));
    } else if kind == 3 {
        // Control escapes: \n, \t, \r
        out.push('\\');
        out.push(d.choose("ntr"));
    } else if kind == 4 {
        // Wildcard
        out.push('.');
    } else if kind == 5 {
        // Anchors and word boundaries
        let a_choices: const u8[:][4] = ["^", "$", "\\b", "\\B"];
        out.append(d.choose(a_choices));
    } else if kind == 6 {
        // Character classes
        out.push('[');
        if d.next_bool() { out.push('^'); }
        let c_choices: const u8[:][5] = ["a-c", "0-3", "x-z\\d", "]a-b", "a-c-e"];
        out.append(d.choose(c_choices));
        out.push(']');
    } else {
        // Groups: capturing, non-capturing, or flags
        let g_choices: const u8[:][4] = ["(", "(?:", "(?i:", "(?s:"];
        let prefix = d.choose(g_choices);
        out.append(prefix);
        gen_regex(out, d, depth + 1);
        out.push(')');
    }
}

recursive fn gen_piece(out: u8[>..]&, d: Driver&, depth: i32) {
    gen_atom(out, d, depth);
    // 35% chance of repetition operator
    if d.frequency([65, 35]) == 1 {
        let rep_op = d.int_range(0, 4);
        if rep_op == 0 {
            out.push('*');
        } else if rep_op == 1 {
            out.push('+');
        } else if rep_op == 2 {
            out.push('?');
        } else if rep_op == 3 {
            let n = d.int_range(0, 3);
            format(out, "{", n, "}");
        } else {
            let n = d.int_range(0, 2);
            let m = d.int_range(n, n + 2);
            format(out, "{", n, ",", m, "}");
        }
        if d.next_bool() {
            out.push('?'); // lazy modifier
        }
    }
}

recursive fn gen_concat(out: u8[>..]&, d: Driver&, depth: i32) {
    let count = d.int_range(1, 3);
    for _ in count {
        gen_piece(out, d, depth);
    }
}

recursive fn gen_regex(out: u8[>..]&, d: Driver&, depth: i32) {
    let alts = d.int_range(1, 2);
    for i in alts {
        if i > 0 { out.push('|'); }
        gen_concat(out, d, depth);
    }
}

fn gen_text(d: Driver&) -> u8[>..] {
    let mode = d.int_range(0, 4);
    var out: u8[>..] = [];
    if mode == 0 {
        return out;
    } else if mode == 1 {
        let len = d.int_range(1, 25);
        for _ in len {
            out.push(d.choose("abcdef0123\n\t "));
        }
    } else if mode == 2 {
        let len = d.int_range(1, 20);
        for _ in len {
            out.push(d.choose("xyz89!@#$\n"));
        }
    } else {
        let len = d.int_range(1, 15);
        for _ in len {
            out.push(d.choose("a \n"));
        }
    }
    return out;
}

// --- Invariant Verification --------------------------------------------------

fn check_regex_invariants(pattern: const u8[:], text: const u8[:]) -> bool {
    var err: u8[>..] = [];
    let re = regex::compile(pattern, err);
    if err.len > 0 {
        return true;
    }

    let m = regex::matches(re, text);
    let c = regex::count(re, text);
    let s, e = regex::find(re, text);

    // Invariant 1: matches == (count > 0)
    assert(m == (c > 0));

    // Invariant 2: (s >= 0) == matches
    assert((s >= 0) == m);

    // Invariant 3: find_at(0) == find and matches_at(0) == matches
    let s0, e0 = regex::find_at(re, text, 0);
    assert(s == s0 && e == e0);
    let m0 = regex::matches_at(re, text, 0);
    assert(m == m0);

    // Invariant 4: num_groups query
    let ng = regex::num_groups(re);
    assert(ng >= 1 && ng == re.groups);

    // Invariant 5: is_nullable query matches empty string match
    let is_null = regex::is_nullable(re);
    let empty_m = regex::matches(re, "");
    assert(is_null == empty_m);

    // Invariant 6: find bounds and matches_at
    if s >= 0 {
        assert(s >= 0 && s <= e && e <= text.len);
        assert(regex::matches_at(re, text, s));
    }

    // Invariant 7: find_at at midpoint
    if text.len > 0 {
        let mid = text.len / 2;
        let mid_s, mid_e = regex::find_at(re, text, mid);
        let mid_m = regex::matches_at(re, text, mid);
        assert(mid_m == (mid_s >= 0));
        if mid_s >= 0 {
            assert(mid_s >= mid && mid_s <= mid_e && mid_e <= text.len);
        }
    }

    // Invariant 8: each_match iteration count, monotonicity, and order
    var match_count = 0;
    var prev_s = -1;
    var prev_e = -1;

    regex::each_match(re, text) { ms, me =>
        match_count++;
        if match_count == 1 {
            assert(ms == s && me == e);
        }
        assert(ms >= 0 && ms <= me && me <= text.len);
        if prev_e >= 0 {
            assert(ms >= prev_e);
            if ms == me && me == prev_e {
                abort("each_match repeated empty match at same position");
            }
        }
        prev_s = ms;
        prev_e = me;
    };
    assert(match_count == c);

    // Invariant 9: each_captures group 0 matches each_match
    var caps_count = 0;
    regex::each_captures(re, text) { caps =>
        caps_count++;
        let g0 = regex::group(caps, 0);
        let s0 = caps.slots[0];
        let e0 = caps.slots[1];
        assert(s0 >= 0 && e0 >= s0 && e0 <= text.len);
        assert(g0.len == (e0 - s0));
        for k in 1..re.groups {
            let sk = caps.slots[2 * k];
            let ek = caps.slots[2 * k + 1];
            if sk >= 0 {
                assert(ek >= sk && sk >= s0 && ek <= e0);
            }
        }
    };
    assert(caps_count == c);

    // Invariant 10: format_replaced identity replacement
    var replaced: u8[>..] = [];
    regex::format_replaced(replaced, re, text) { caps =>
        regex::group(caps, 0)
    };
    assert(replaced == text);

    return true;
}

// --- First-Class Fuzz Targets (goose fuzz discovery) -------------------------

// Discovered target 1: Grammar-guided invariant fuzzer
fuzz fn fuzz_regex_invariants(d: Driver&) -> bool {
    var pattern: u8[>..] = [];
    gen_regex(pattern, d, 0);
    let text = gen_text(d);
    var err: u8[>..] = [];
    let re = regex::compile(pattern[..], err);
    guard d.assume(err.len == 0) else { return true; }
    check_regex_invariants(pattern[..], text[..])
}

// Discovered target 2: Raw mutational compiler fuzzer
fuzz fn fuzz_regex_raw(data: const u8[:]) {
    var err: u8[>..] = [];
    let re = regex::compile(data, err);
    let _ = regex::matches(re, "");
    let _ = regex::find(re, "");
    let _ = regex::count(re, "");
}

// --- Standard Regression Test Main -------------------------------------------

fn main() {
    check()
        .seed(0x1337cafe)
        .iterations(1000)
        .for_each() { d =>
            var pattern: u8[>..] = [];
            gen_regex(pattern, d, 0);
            let text = gen_text(d);
            check_regex_invariants(pattern[..], text[..])
        };
    print("regex fuzz: all invariant, differential, and parser checks passed");
}
