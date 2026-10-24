import std;
import regex;

fn main() {
    // 1. Start anchor on large text without matches
    var big: u8[>..] = [];
    for _ in 20000 { big.push('a'); }
    let re_start = regex::compile("^b+");
    let s0, e0 = regex::find(re_start, big[..]);
    print("start anchor on 20k no match: ", s0, " ", e0);

    // 2. Start anchor with match after newline in large text
    var multiline: u8[>..] = [];
    for _ in 10000 { multiline.push('a'); }
    multiline.push('\n');
    multiline.append("bbb\n");
    for _ in 10000 { multiline.push('a'); }
    let s1, e1 = regex::find(re_start, multiline[..]);
    print("start anchor match after newline: ", s1, " ", e1);

    // 3. Captures with start anchor
    let re_cap = regex::compile("^(b+)");
    regex::each_captures(re_cap, multiline[..]) { c =>
        print("capture group 1: ", regex::group(c, 1));
    };

    // 4. End anchor on large text
    let re_end = regex::compile("b+$");
    let s2, e2 = regex::find(re_end, big[..]);
    print("end anchor on 20k no match: ", s2, " ", e2);

    let s3, e3 = regex::find(re_end, multiline[..]);
    print("end anchor match before newline: ", s3, " ", e3);

    // 5. Word boundaries on large text
    let re_wb = regex::compile("\\btarget\\b");
    var wb_text: u8[>..] = [];
    for _ in 10000 { wb_text.push('a'); }
    wb_text.push(' ');
    wb_text.append("target");
    wb_text.push(' ');
    for _ in 10000 { wb_text.push('a'); }
    let s4, e4 = regex::find(re_wb, wb_text[..]);
    print("word boundary in 20k: ", s4, " ", e4);

    // 6. Non-word boundary
    let re_nwb = regex::compile("\\Bfoo\\B");
    let s5, e5 = regex::find(re_nwb, "afoob");
    let s6, e6 = regex::find(re_nwb, " foo ");
    print("non-word boundary: ", s5, " ", e5, " / ", s6, " ", e6);

    // 7. Empty line matches with ^$
    let re_empty = regex::compile("^$");
    var empty_count = 0;
    regex::each_match(re_empty, "a\n\nb") { s, e =>
        empty_count++;
    };
    print("empty line count: ", empty_count);
}
