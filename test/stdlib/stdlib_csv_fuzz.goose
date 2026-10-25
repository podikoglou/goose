// runtime-debug: stdlib/csv fuzzing, structured roundtrip fidelity, and parser robustness.
import std;
import csv;
import proptest;

// --- Unescaping and Formatting Helpers ----------------------------------------

// Replaces doubled quotes "" with a single quote " to recover the original field.
fn unescape_field(out: u8[>..]&, f: const u8[:]) {
    format_replaced(out, f, "\"\"", "\"");
}

// --- Structured Generator ----------------------------------------------------

recursive fn gen_field(out: u8[>..]&, d: Driver&, sep: u8) {
    let mode = d.int_range(0, 5);
    if mode == 0 {
        // Empty string
        return;
    } else if mode == 1 {
        // Plain alphanumeric string
        let len = d.int_range(1, 12);
        let s = d.alphanumeric(len);
        out.append(s);
    } else if mode == 2 {
        // String drawn from special and control characters
        let len = d.int_range(1, 10);
        let s = d.string_from(" ,;|\t:\"'\r\nabcxyz012", len);
        out.append(s);
    } else if mode == 3 {
        // Tricky edge cases: quotes, newlines, CRLF, spaces, tabs
        let edge_cases: const u8[:][16] = [
            "\"",
            "\"\"",
            "\"\"\"",
            "\"\"\"\"",
            "\"hello\"",
            "\n",
            "\r\n",
            "\r",
            "hello\nworld",
            "hello\r\nworld",
            " ",
            "   ",
            " a ",
            "\t",
            ",",
            ";"
        ];
        out.append(d.choose(edge_cases));
    } else if mode == 4 {
        // Separator-specific edge cases
        let c = d.int_range(0, 3);
        if c == 0 {
            out.push(sep);
        } else if c == 1 {
            format(out, "a", sep, "b");
        } else if c == 2 {
            format(out, "\"", sep, "\"\n");
        } else {
            format(out, "col1", sep, "col2", sep);
        }
    } else {
        // Compound recursive construction
        if d.can_recurse() {
            d.recurse() { drv =>
                let parts = drv.int_range(1, 3);
                for _ in parts {
                    gen_field(out, drv, sep);
                }
            };
        } else {
            let s = d.alphanumeric(1, 6);
            out.append(s);
        }
    }
}

recursive fn gen_table(
    raw_fields: u8[>..]&,
    field_ends: i64[>..]&,
    row_counts: i64[>..]&,
    d: Driver&,
    sep: u8
) {
    let num_rows = d.int_range(0, 8);
    for _ in num_rows {
        if d.can_recurse() {
            d.recurse() { row_drv =>
                let num_cols = row_drv.int_range(1, 6);
                row_counts.push(num_cols);
                for _ in num_cols {
                    var field: u8[>..] = [];
                    gen_field(field, row_drv, sep);
                    raw_fields.append(field);
                    field_ends.push(raw_fields.len);
                }
            };
        } else {
            let num_cols = d.int_range(1, 4);
            row_counts.push(num_cols);
            for _ in num_cols {
                var field: u8[>..] = [];
                gen_field(field, d, sep);
                raw_fields.append(field);
                field_ends.push(raw_fields.len);
            }
        }
    }
}

fn format_table(
    csv_text: u8[>..]&,
    raw_fields: const u8[:],
    field_ends: const i64[:],
    row_counts: const i64[:],
    d: Driver&,
    sep: u8
) {
    var field_idx = 0;
    var last_field_empty = false;
    for row_len, r in row_counts {
        for c in row_len {
            if c > 0 { csv_text.push(sep); }
            let start = if field_idx == 0 { 0 } else { field_ends[field_idx - 1] };
            let end = field_ends[field_idx];
            let f = raw_fields[start..end];
            csv::format_field(csv_text, f, sep);
            last_field_empty = (f.len == 0);
            field_idx++;
        }
        let is_last = (r == row_counts.len - 1);
        let can_omit_break = is_last && (row_len > 1 || !last_field_empty);

        let term_choice = d.int_range(0, if can_omit_break { 2 } else { 1 });
        if term_choice == 0 {
            csv_text.push('\n');
        } else if term_choice == 1 {
            csv_text.append("\r\n");
        }
    }
}

// --- Roundtrip Validation Invariant ------------------------------------------

fn run_csv_roundtrip(d: Driver&, sep: u8) -> bool {
    var raw_fields: u8[>..] = [];
    var field_ends: i64[>..] = [];
    var row_counts: i64[>..] = [];

    gen_table(raw_fields, field_ends, row_counts, d, sep);

    var csv_text: u8[>..] = [];
    format_table(csv_text, raw_fields[..], field_ends[..], row_counts[..], d, sep);

    var parsed_records = 0;
    var parsed_fields = 0;
    var field_cursor = 0;

    let ok = csv::each_record(csv_text[..], sep) { fields =>
        if parsed_records >= row_counts.len {
            abort("csv roundtrip invariant: parsed more records than generated");
        }
        let expected_field_count = row_counts[parsed_records];
        if fields.len != expected_field_count {
            abort("csv roundtrip invariant: record field count mismatch");
        }
        for f in fields {
            var got: u8[>..] = [];
            unescape_field(got, f);

            let start = if field_cursor == 0 { 0 } else { field_ends[field_cursor - 1] };
            let end = field_ends[field_cursor];
            let want = raw_fields[start..end];

            if got != want {
                abort("csv roundtrip invariant: field content mismatch");
            }
            field_cursor++;
            parsed_fields++;
        }
        parsed_records++;
    };

    if !ok {
        abort("csv roundtrip invariant: each_record returned false on formatted CSV");
    }
    if parsed_records != row_counts.len {
        abort("csv roundtrip invariant: total record count mismatch");
    }
    if parsed_fields != field_ends.len {
        abort("csv roundtrip invariant: total field count mismatch");
    }
    return true;
}

// --- First-Class Fuzz Targets (discovered by `goose fuzz`) -------------------

// Target 1: Raw mutational byte fuzzer
// Invariant: Must never crash, panic, abort, or read out of bounds on arbitrary corrupt bytes.
fuzz fn fuzz_csv_raw(data: const u8[:]) {
    var record_count = 0;
    var field_count = 0;
    let ok = csv::each_record(data) { fields =>
        record_count++;
        field_count += fields.len;
        for f in fields {
            // Memory safety: verify slice bounds by reading all bytes
            for b in f {
                let _ = b;
            }
            // Invariant: field unescaping must never crash or read out of bounds
            var unescaped: u8[>..] = [];
            unescape_field(unescaped, f);

            // Invariant: formatting extracted field must succeed without crashing
            var formatted: u8[>..] = [];
            csv::format_field(formatted, f);
        }
    };

    // Invariant: formatting arbitrary bytes directly must succeed without crashing
    var out: u8[>..] = [];
    csv::format_field(out, data);
    let _ = ok;
}

// Target 2: Structured 2D table roundtrip fuzzer (standard comma separator)
// Invariant: Roundtrip fidelity (every row and every field matches exactly).
fuzz fn fuzz_csv_roundtrip(d: Driver&) -> bool {
    run_csv_roundtrip(d, ',')
}

// Target 3: Custom separator fuzzer (TSV \t, semicolon ;, pipe |, colon :, space, etc.)
// Invariant: Roundtrip fidelity and robustness with arbitrary valid delimiters.
fuzz fn fuzz_csv_custom_sep(d: Driver&) -> bool {
    let mode = d.int_range(0, 3);
    var sep: u8 = '\t';
    if mode == 0 {
        // TSV
        sep = '\t';
    } else if mode == 1 {
        // Semicolon
        sep = ';';
    } else if mode == 2 {
        // Pipe
        sep = '|';
    } else {
        // Other delimiters: colon, space, caret, tilde, slash, hash
        let choices: const u8[:][6] = [":", " ", "^", "~", "/", "#"];
        let choice = d.int_range(0, choices.len - 1);
        sep = choices[choice][0];
    }

    // Roundtrip fidelity with custom separator
    run_csv_roundtrip(d, sep)
}

// --- Regression / Proptest Suite --------------------------------------------

fn main() {
    print("running structured csv property test...");

    // 1. Standard CSV roundtrip fuzzing
    check()
        .seed(0x4353562c) // "CSV,"
        .iterations(1000)
        .for_each() { d =>
            fuzz_csv_roundtrip(d)
        };

    // 2. Custom separator roundtrip fuzzing (TSV, semicolon, pipe, colon, space, etc.)
    check()
        .seed(0x53455053) // "SEPS"
        .iterations(1000)
        .for_each() { d =>
            fuzz_csv_custom_sep(d)
        };

    // 3. Raw byte regressions
    let edge_cases: const u8[:][24] = [
        "",
        ",",
        ",,",
        "\n",
        "\r\n",
        "\r",
        "\"",
        "\"\"",
        "\"\"\"",
        "\"\"\"\"",
        "a",
        "a,b",
        "a,b\n",
        "a,b\r\nc,d\r\n",
        "\"a,b\",\"c\"\"d\",\n",
        "ok\na\"b,c\n",
        "ok\n\"abc\nd",
        "ok\n\"a\"b,c\n",
        "\"a\"\rb\n",
        "\"a\" ,b\n",
        " , , \n",
        "\t\t\t\n",
        ";;;",
        "|||\n"
    ];
    for c in edge_cases {
        fuzz_csv_raw(c);
    }

    // 4. Raw byte fuzzing through driver
    check()
        .seed(0x72617762) // "rawb"
        .iterations(500)
        .for_each() { d =>
            let raw = d.bytes(0, 128);
            fuzz_csv_raw(raw[..]);
            true
        };

    print("csv fuzz: all structured invariant, roundtrip, and robustness checks passed");
}
