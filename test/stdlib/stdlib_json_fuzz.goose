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

// --- Structured Generator ----------------------------------------------------

recursive fn gen_json_value(out: u8[>..]&, d: Driver&, depth: i32) {
    let container_weight = if depth < 4 { 15 } else { 0 };
    // [null, bool, int, num, str, arr, obj]
    let weights: i64[7] = [10, 15, 20, 20, 25, container_weight, container_weight];
    let kind = d.frequency(weights);

    if kind == 0 {
        out.append("null");
    } else if kind == 1 {
        out.append(if d.next_bool() { "true" } else { "false" });
    } else if kind == 2 {
        let int_choice = d.int_range(0, 5);
        if int_choice == 0 {
            out.push('0');
        } else if int_choice == 1 {
            format(out, d.next_i64());
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
            json::format_number(out, d.next_f64());
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
                out.push(d.choose("abcdef0123+-*/ =_!@#$%^&()"));
            }
        }
        out.push('"');
    } else if kind == 5 {
        // Array
        out.push('[');
        let count = d.int_range(0, 4);
        for i in count {
            if i > 0 { out.push(','); }
            gen_json_value(out, d, depth + 1);
        }
        out.push(']');
    } else {
        // Object
        out.push('{');
        let count = d.int_range(0, 4);
        for i in count {
            if i > 0 { out.push(','); }
            out.push('"');
            out.push(d.choose("abcdefg"));
            format(out, i);
            out.append("\":");
            gen_json_value(out, d, depth + 1);
        }
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
        // Invariant: node count must match
        if doc.len != doc2.len {
            print("Node count mismatch: orig=", doc.len, " reparse=", doc2.len);
            abort("roundtrip node count mismatch");
        }
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
    gen_json_value(text, d, 0);

    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, err = json::parse(text[..], doc, decoded);
    if root == null {
        print("Generated valid JSON failed to parse: ", text);
        print("Error: ", err);
        abort("structured generated JSON parse failed");
    }

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
    if doc.len != doc2.len {
        abort("structured generated JSON node count mismatch");
    }
    return true;
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
    print("json fuzz: all structured invariant checks passed");
}
