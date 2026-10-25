// runtime-debug: stdlib/json fuzzing, structured invariant validation, parser and reader robustness.
import std;
import json;
import proptest;

// --- AST Serialization Helper ------------------------------------------------

fn serialize_doc(out: u8[>..]&, doc: json::Node[>..]&) {
    var left: i64[>..<] = [];
    var obj: bool[>..<] = [];
    var first = false;
    for &n in doc {
        if left.len > 0 {
            if !first { out.push(','); }
            if obj[obj.len - 1] { json::format_key(out, n.key); }
            left[left.len - 1] -= 1;
        }
        first = false;
        match n.val {
            Null => { out.append("null"); },
            Bool b => { json::format_bool(out, b.v); },
            Int i => { json::format_int(out, i.v); },
            Num x => { json::format_number(out, x.v); },
            Str s => { json::format_string(out, s.s); },
            Arr a => { out.push('['); left.push(a.count); obj.push(false); first = true; },
            Obj o => { out.push('{'); left.push(o.count); obj.push(true); first = true; },
        }
        while left.len > 0 && left[left.len - 1] == 0 {
            out.push(if obj[obj.len - 1] { '}' } else { ']' });
            left.pop();
            obj.pop();
            first = false;
        }
    }
}

// --- Semantic AST Invariant Validation and Deep Tree Walking ----------------

fn validate_node_accessors(n: json::Node?) {
    guard n else { return; }
    match n.val {
        Null => {
            let _, b_ok = json::as_bool(n);
            let _, i_ok = json::as_i64(n);
            let _, f_ok = json::as_f64(n);
            let _, s_ok = json::as_string(n);
            if b_ok || i_ok || f_ok || s_ok {
                abort("validate_node_accessors: Null node accessor returned true");
            }
        },
        Bool b => {
            let b_val, b_ok = json::as_bool(n);
            if !b_ok || b_val != b.v {
                abort("validate_node_accessors: as_bool mismatch");
            }
            let _, i_ok = json::as_i64(n);
            let _, f_ok = json::as_f64(n);
            let _, s_ok = json::as_string(n);
            if i_ok || f_ok || s_ok {
                abort("validate_node_accessors: Bool unexpected accessor true");
            }
        },
        Int i => {
            let i_val, i_ok = json::as_i64(n);
            if !i_ok || i_val != i.v {
                abort("validate_node_accessors: as_i64 mismatch");
            }
            let f_val, f_ok = json::as_f64(n);
            if !f_ok || f_val != i.v {
                abort("validate_node_accessors: as_f64 for Int mismatch");
            }
            let _, b_ok = json::as_bool(n);
            let _, s_ok = json::as_string(n);
            if b_ok || s_ok {
                abort("validate_node_accessors: Int unexpected accessor true");
            }
        },
        Num x => {
            let f_val, f_ok = json::as_f64(n);
            if !f_ok {
                abort("validate_node_accessors: as_f64 for Num failed");
            }
            let is_nan = x.v != x.v;
            if !is_nan && f_val != x.v && json::bits_of(f_val) != json::bits_of(x.v) {
                abort("validate_node_accessors: as_f64 for Num mismatch");
            }
            let _, i_ok = json::as_i64(n);
            let _, b_ok = json::as_bool(n);
            let _, s_ok = json::as_string(n);
            if i_ok || b_ok || s_ok {
                abort("validate_node_accessors: Num unexpected accessor true");
            }
        },
        Str s => {
            let s_val, s_ok = json::as_string(n);
            if !s_ok || s_val != s.s {
                abort("validate_node_accessors: as_string mismatch");
            }
            let _, i_ok = json::as_i64(n);
            let _, f_ok = json::as_f64(n);
            let _, b_ok = json::as_bool(n);
            if i_ok || f_ok || b_ok {
                abort("validate_node_accessors: Str unexpected accessor true");
            }
        },
        Arr => {
            let _, b_ok = json::as_bool(n);
            let _, i_ok = json::as_i64(n);
            let _, f_ok = json::as_f64(n);
            let _, s_ok = json::as_string(n);
            if b_ok || i_ok || f_ok || s_ok {
                abort("validate_node_accessors: Arr unexpected accessor true");
            }
        },
        Obj => {
            let _, b_ok = json::as_bool(n);
            let _, i_ok = json::as_i64(n);
            let _, f_ok = json::as_f64(n);
            let _, s_ok = json::as_string(n);
            if b_ok || i_ok || f_ok || s_ok {
                abort("validate_node_accessors: Obj unexpected accessor true");
            }
        },
    }
}

recursive fn walk_doc_invariants(n: json::Node?, max_nodes: i64, visited: i64&) {
    guard n else { return; }
    visited++;
    if visited > max_nodes {
        abort("ast invariant: cycle detected in tree walk");
    }

    validate_node_accessors(n);

    match n.val {
        Arr a => {
            var count: i64 = 0;
            var c = n.first;
            while c {
                count++;
                if count > max_nodes {
                    abort("ast invariant: cycle detected in Arr sibling list");
                }
                if c.key.len != 0 {
                    abort("ast invariant: array element has non-empty key");
                }
                walk_doc_invariants(c, max_nodes, visited);
                c .= c.next;
            }
            if count != a.count {
                abort("ast invariant: Arr child count mismatch");
            }

            var each_count: i64 = 0;
            json::each(n) { _ => each_count++; };
            if each_count != count {
                abort("ast invariant: json::each count mismatch with first/next traversal");
            }

            if json::member(n, "key") != null {
                abort("ast invariant: json::member on Arr returned non-null");
            }
        },
        Obj o => {
            var count: i64 = 0;
            var c = n.first;
            while c {
                count++;
                if count > max_nodes {
                    abort("ast invariant: cycle detected in Obj sibling list");
                }
                // Test json::member on object: for every child, json::member(parent, child.key) must find a node with that key
                let found = json::member(n, c.key);
                if found == null {
                    abort("ast invariant: json::member failed to find existing child key");
                }
                if found.key != c.key {
                    abort("ast invariant: json::member returned node with different key");
                }
                walk_doc_invariants(c, max_nodes, visited);
                c .= c.next;
            }
            if count != o.count {
                abort("ast invariant: Obj child count mismatch");
            }

            var each_count: i64 = 0;
            json::each(n) { _ => each_count++; };
            if each_count != count {
                abort("ast invariant: json::each count mismatch with first/next traversal");
            }
        },
        _ => {
            // Non-container nodes must have n.first == null
            if n.first != null {
                abort("ast invariant: non-container node has first != null");
            }
            // Non-container nodes must return null for member lookups
            if json::member(n, "key") != null {
                abort("ast invariant: json::member on non-container returned non-null");
            }
        },
    }
}

fn assert_doc_invariants(root: json::Node?, doc: json::Node[>..]&) {
    if root == null {
        if doc.len != 0 {
            abort("ast invariant: root is null but doc.len != 0");
        }
        return;
    }
    if root.next != null {
        abort("ast invariant: root.next is not null");
    }
    if root.key.len != 0 {
        abort("ast invariant: root.key is not empty");
    }

    var visited: i64 = 0;
    walk_doc_invariants(root, doc.len, visited);
    if visited != doc.len {
        abort("ast invariant: reachable node count does not match doc.len");
    }

    for &n in doc {
        match n.val {
            Arr => {},
            Obj => {},
            _ => {
                if n.first != null {
                    abort("ast invariant: flat check non-container first != null");
                }
            },
        }
    }
}

recursive fn assert_nodes_equal(n1: json::Node?, n2: json::Node?) {
    if n1 == null && n2 == null { return; }
    guard n1 && n2 else {
        abort("assert_nodes_equal: null mismatch");
    }
    if n1.key != n2.key {
        abort("assert_nodes_equal: key mismatch");
    }
    match n1.val {
        Null => {
            match n2.val {
                Null => {},
                _ => { abort("assert_nodes_equal: expected Null"); },
            }
        },
        Bool b1 => {
            match n2.val {
                Bool b2 => {
                    if b1.v != b2.v { abort("assert_nodes_equal: Bool mismatch"); }
                },
                _ => { abort("assert_nodes_equal: expected Bool"); },
            }
        },
        Int i1 => {
            match n2.val {
                Int i2 => {
                    if i1.v != i2.v { abort("assert_nodes_equal: Int mismatch"); }
                },
                _ => { abort("assert_nodes_equal: expected Int"); },
            }
        },
        Num x1 => {
            let is_inf_or_nan = (x1.v - x1.v != 0.0) || (x1.v != x1.v);
            if is_inf_or_nan {
                match n2.val {
                    Null => {},
                    _ => { abort("assert_nodes_equal: expected Null for non-finite Num"); },
                }
            } else {
                match n2.val {
                    Num x2 => {
                        if json::bits_of(x1.v) != json::bits_of(x2.v) {
                            abort("assert_nodes_equal: Num bit mismatch");
                        }
                    },
                    _ => { abort("assert_nodes_equal: expected Num"); },
                }
            }
        },
        Str s1 => {
            match n2.val {
                Str s2 => {
                    if s1.s != s2.s { abort("assert_nodes_equal: Str mismatch"); }
                },
                _ => { abort("assert_nodes_equal: expected Str"); },
            }
        },
        Arr a1 => {
            match n2.val {
                Arr a2 => {
                    if a1.count != a2.count { abort("assert_nodes_equal: Arr count mismatch"); }
                },
                _ => { abort("assert_nodes_equal: expected Arr"); },
            }
        },
        Obj o1 => {
            match n2.val {
                Obj o2 => {
                    if o1.count != o2.count { abort("assert_nodes_equal: Obj count mismatch"); }
                },
                _ => { abort("assert_nodes_equal: expected Obj"); },
            }
        },
    }

    var c1 = n1.first;
    var c2 = n2.first;
    while c1 || c2 {
        guard c1 && c2 else {
            abort("assert_nodes_equal: sibling child count mismatch");
        }
        assert_nodes_equal(c1, c2);
        c1 .= c1.next;
        c2 .= c2.next;
    }
}


// --- Structured Generator ----------------------------------------------------

recursive fn gen_json_value(out: u8[>..]&, d: Driver&) {
    let container_weight = if d.can_recurse() { 15 } else { 0 };
    // [null, bool, int, num, str, arr, obj]
    let weights: i64[7] = [10, 15, 20, 20, 25, container_weight, container_weight];
    let kind = d.frequency(weights);

    if kind == 0 {
        out.append("null");
    } else if kind == 1 {
        out.append(if d.boolean() { "true" } else { "false" });
    } else if kind == 2 {
        let int_choice = d.int_range(0, 5);
        if int_choice == 0 {
            out.push('0');
        } else if int_choice == 1 {
            format(out, d.gen_i64());
        } else if int_choice == 2 {
            // Edge integers
            let edges: i64[4] = [9223372036854775807, -9223372036854775807, 2147483647, -2147483648];
            format(out, d.choose(edges));
        } else {
            format(out, d.int_range(-1000000, 1000000));
        }
    } else if kind == 3 {
        let num_choice = d.int_range(0, 4);
        if num_choice == 0 {
            json::format_number(out, d.gen_f64());
        } else if num_choice == 1 {
            // Exponent notations
            let mant = d.int_range(-99, 99);
            let exp = d.int_range(-30, 30);
            format(out, mant, "e", exp);
        } else if num_choice == 2 {
            // Fractionals
            let whole = d.int_range(0, 100);
            let frac = d.int_range(0, 99999);
            format(out, whole, ".", frac);
        } else {
            out.append("0.0");
        }
    } else if kind == 4 {
        // String with potential escapes
        out.push('"');
        let str_len = d.int_range(0, 8);
        for _ in str_len {
            let esc = d.int_range(0, 8);
            if esc == 0 {
                out.append("\\\"");
            } else if esc == 1 {
                out.append("\\\\");
            } else if esc == 2 {
                out.append("\\n");
            } else if esc == 3 {
                out.append("\\t");
            } else if esc == 4 {
                // Unicode escape
                let hex: const u8[:][4] = ["0041", "0020", "0000", "007f"];
                out.append("\\u");
                out.append(d.choose(hex));
            } else {
                let s = d.string_from("abcdef0123+-*/ =_!@#$%^&()", 1);
                out.append(s);
            }
        }
        out.push('"');
    } else if kind == 5 {
        // Array
        out.push('[');
        d.recurse() { drv =>
            let count = drv.int_range(0, 4);
            for i in count {
                if i > 0 { out.push(','); }
                gen_json_value(out, drv);
            }
        };
        out.push(']');
    } else {
        // Object
        out.push('{');
        d.recurse() { drv =>
            let count = drv.int_range(0, 4);
            for i in count {
                if i > 0 { out.push(','); }
                out.push('"');
                {
                    let key = drv.alphanumeric(1, 4);
                    out.append(key);
                }
                format(out, i);
                out.append("\":");
                gen_json_value(out, drv);
            }
        };
        out.push('}');
    }
}

// --- First-Class Fuzz Targets (discovered by `goose fuzz`) -------------------

// 1. Raw byte slice parser fuzz target
fuzz fn fuzz_json_parser(data: const u8[:]) {
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, err = json::parse(data, doc, decoded);
    if root != null {
        // Structural integrity and invariant validation on doc
        assert_doc_invariants(root, doc);

        // Parse succeeded: serialization must succeed and never crash
        var serialized: u8[>..] = [];
        serialize_doc(serialized, doc);

        // Re-parsing serialized output must succeed
        var doc2: json::Node[>..] = [];
        var decoded2: u8[>..] = [];
        let root2, err2 = json::parse(serialized[..], doc2, decoded2);
        if root2 == null {
            print("Failed to re-parse serialized JSON!");
            print("Original input: ", data);
            print("Serialized: ", serialized);
            print("Error: ", err2);
            abort("roundtrip re-parse failed");
        }

        // Structural integrity and invariant validation on doc2
        assert_doc_invariants(root2, doc2);

        // Invariant: node count must match
        if doc.len != doc2.len {
            print("Node count mismatch: orig=", doc.len, " reparse=", doc2.len);
            abort("roundtrip node count mismatch");
        }

        // Deep semantic AST equality check
        assert_nodes_equal(root, root2);
    }
}

// 2. Raw streaming reader fuzz target
fuzz fn fuzz_json_reader(data: const u8[:]) {
    var r = json::reader(data);
    var scratch: u8[>..] = [];
    while r.pos < data.len && r.error.len == 0 {
        let c = json::peek(r);
        if c == 0 {
            break;
        }
        if c == '{' || c == '[' {
            json::skip(r);
        } else if c == '"' {
            let _ = json::read_string(r, scratch);
        } else if (c >= '0' && c <= '9') || c == '-' {
            let _ = json::read_number(r);
        } else if c == 't' || c == 'f' {
            let _ = json::read_bool(r);
        } else if c == 'n' {
            json::word(r, "null");
        } else {
            // Malformed character, reader should fail gracefully
            json::skip(r);
            break;
        }
    }
    let _ = json::finish(r);
}

// 3. Structured generator fuzz target
fuzz fn fuzz_json_structured(d: Driver&) -> bool {
    var text: u8[>..] = [];
    gen_json_value(text, d);

    // Differential validation on generated valid JSON
    fuzz_json_differential(text[..]);

    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, err = json::parse(text[..], doc, decoded);
    if root == null {
        print("Generated valid JSON failed to parse: ", text);
        print("Error: ", err);
        abort("structured generated JSON parse failed");
    }

    // Structural integrity and invariant validation on doc
    assert_doc_invariants(root, doc);

    var serialized: u8[>..] = [];
    serialize_doc(serialized, doc);

    var doc2: json::Node[>..] = [];
    var decoded2: u8[>..] = [];
    let root2, err2 = json::parse(serialized[..], doc2, decoded2);
    if root2 == null {
        print("Serialized generated JSON failed to reparse: ", serialized);
        print("Error: ", err2);
        abort("structured generated JSON reparse failed");
    }

    // Structural integrity and invariant validation on doc2
    assert_doc_invariants(root2, doc2);

    if doc.len != doc2.len {
        abort("structured generated JSON node count mismatch");
    }

    // Deep semantic AST equality check
    assert_nodes_equal(root, root2);
    return true;
}

// 4. Differential fuzz target: AST parser vs streaming reader
fuzz fn fuzz_json_differential(data: const u8[:]) {
    // 1. AST Parser
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, parse_err = json::parse(data, doc, decoded);
    let parse_ok = (root != null);
    if parse_ok {
        assert_doc_invariants(root, doc);
    }

    // 2. Streaming Reader validation via skip + finish
    var r = json::reader(data);
    json::skip(r);
    let r_ok = json::finish(r);

    // Invariant 1: AST Parser acceptance iff Streaming Reader acceptance
    if parse_ok != r_ok {
        print("Differential acceptance mismatch on input (len ", data.len, "): ", data);
        print("  json::parse:  ok=", parse_ok, " err='", parse_err, "'");
        print("  json::reader: ok=", r_ok, " err='", r.error, "' at byte ", r.error_at);
        abort("differential acceptance mismatch between json::parse and json::reader");
    }

    // Additional semantic cross-validation when both accept:
    if root {
        match root.val {
            Null => {
                var r2 = json::reader(data);
                let c = json::peek(r2);
                if c == 'n' {
                    json::word(r2, "null");
                }
                if !json::finish(r2) {
                    abort("differential reader failed reading null root");
                }
            },
            Bool b => {
                var r2 = json::reader(data);
                let val = json::read_bool(r2);
                if !json::finish(r2) || val != b.v {
                    abort("differential reader failed reading bool root");
                }
            },
            Int i => {
                var r2 = json::reader(data);
                let val = json::read_int(r2);
                if !json::finish(r2) || val != i.v {
                    abort("differential reader failed reading int root");
                }
            },
            Num x => {
                var r2 = json::reader(data);
                let val = json::read_number(r2);
                if !json::finish(r2) {
                    abort("differential reader failed reading number root");
                }
                if val != x.v && !(val != val && x.v != x.v) {
                    abort("differential reader number value mismatch");
                }
            },
            Str s => {
                var r2 = json::reader(data);
                var scratch: u8[>..] = [];
                let val = json::read_string(r2, scratch);
                if !json::finish(r2) || val != s.s {
                    abort("differential reader failed reading string root");
                }
            },
            Arr a => {
                var r2 = json::reader(data);
                var elem_count = 0;
                json::each_element(r2) {
                    json::skip(r2);
                    elem_count++;
                };
                if !json::finish(r2) || elem_count != a.count {
                    abort("differential reader failed reading array root elements");
                }
            },
            Obj o => {
                var r2 = json::reader(data);
                var member_count = 0;
                json::each_member(r2) { _ =>
                    json::skip(r2);
                    member_count++;
                };
                if !json::finish(r2) || member_count != o.count {
                    abort("differential reader failed reading object root members");
                }
            },
        }
    }
}

// --- Regression / Proptest Suite --------------------------------------------

fn main() {
    print("running structured json property test...");
    check()
        .seed(0x4a534f4e)
        .iterations(1000)
        .for_each() { d =>
            fuzz_json_structured(d)
        };

    // Regression suite for differential fuzz target
    let cases: const u8[:][20] = [
        "",
        " ",
        "null",
        "true",
        "false",
        "0",
        "-0",
        "123",
        "-9223372036854775807",
        "123.456",
        "1e5",
        "\"hello\"",
        "\"\\u0041\\u0020\"",
        "[]",
        "{}",
        "[1, 2, 3]",
        "{\"a\": 1}",
        "{\"a\": 1, \"b\": [2, 3]}",
        "invalid",
        "{\"unclosed\": "
    ];
    for c in cases {
        fuzz_json_differential(c);
    }

    check()
        .seed(0xd1ff32)
        .iterations(500)
        .for_each() { d =>
            let raw = d.bytes(0, 128);
            fuzz_json_differential(raw[..]);
            true
        };

    print("json fuzz: all structured invariant checks passed");
}
