// runtime-debug: string join and replace returning convenience forms
import std;
import regex;

fn test_std_join() {
    let empty_parts: const u8[:][] = [];
    let r0 = join(empty_parts[..], ", ");
    print("join empty: len=", r0.len, " '", r0, "'");

    let single: const u8[:][] = ["hello"];
    let r1 = join(single[..], ", ");
    print("join single: '", r1, "'");

    let parts: const u8[:][] = ["foo", "bar", "baz"];
    let r2 = join(parts[..], "-");
    print("join multi: '", r2, "'");

    let r3 = join(parts[..], "");
    print("join empty sep: '", r3, "'");

    let r4 = join(parts[..], " <-> ");
    print("join wide sep: '", r4, "'");

    // UFCS
    let r5 = parts[..].join("::");
    print("join ufcs: '", r5, "'");
}

fn test_std_replace() {
    let r0 = replace("hello world", "", "xyz");
    print("replace empty old: '", r0, "'");

    let r1 = replace("hello world", "abc", "xyz");
    print("replace no match: '", r1, "'");

    let r2 = replace("hello world", "world", "goose");
    print("replace single: '", r2, "'");

    let r3 = replace("the cat sat on the mat", "at", "og");
    print("replace multi: '", r3, "'");

    let r4 = replace("aaaa", "aa", "b");
    print("replace overlap: '", r4, "'");

    let r5 = replace("a,b,c,d", ",", "");
    print("replace remove: '", r5, "'");

    let r6 = replace("test", "test", "done");
    print("replace exact: '", r6, "'");

    let r7 = replace("", "a", "b");
    print("replace empty src: '", r7, "'");

    // UFCS
    let s = "quick brown fox";
    let r8 = s.replace("brown", "red");
    print("replace ufcs: '", r8, "'");
}

fn test_regex_replace() {
    let re_tpl = regex::compile("""\{\{\s*(\w+)\s*\}\}""");
    let tpl = "Hello {{ name }}, welcome to {{ place }}!";
    let r0 = regex::replace(re_tpl, tpl) { caps =>
        let key = regex::group(caps, 1);
        if key == "name" {
            "Alice"
        } else if key == "place" {
            "Wonderland"
        } else {
            "unknown"
        }
    };
    print("regex replace tpl: '", r0, "'");

    let r1 = regex::replace(re_tpl, "no template variables here") { caps =>
        "replaced"
    };
    print("regex replace no match: '", r1, "'");

    let re_num = regex::compile("\\d+");
    let r2 = regex::replace(re_num, "order: 10 items, 25 dollars, 5 bonus") { caps =>
        let val, ok = parse_int(regex::group(caps, 0));
        var buf: u8[>..] = [];
        format(buf, val * 2);
        buf
    };
    print("regex replace transform: '", r2, "'");

    let r3 = regex::replace(re_num, "1 a 2 b 3 c") { caps =>
        "#"
    };
    print("regex replace multi: '", r3, "'");
}

fn main() {
    test_std_join();
    test_std_replace();
    test_regex_replace();
}
