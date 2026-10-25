// Property verification test fixture: Stacking multiple properties above a function
import std;

prop "idempotent" for xs {
    sort(sort(xs)) == sort(xs)
}

prop "preserves length" for xs {
    sort(xs).len == xs.len
}
fn sort(xs: const i64[:]) -> i64[>..] {
    var out: i64[>..] = [];
    for x in xs { out.push(x); }
    var i = 1;
    while i < out.len {
        var j = i;
        while j > 0 && out[j - 1] > out[j] {
            let tmp = out[j - 1];
            out[j - 1] = out[j];
            out[j] = tmp;
            j -= 1;
        }
        i += 1;
    }
    out
}

fn sort(xs: i64[>..]) -> i64[>..] {
    sort(xs[..])
}

fn main() {
    let raw: i64[] = [5, 3, 1, 4, 2];
    let s = sort(raw[..]);
    if s.len != 5 { abort("len mismatch"); }
    if s[0] != 1 || s[4] != 5 { abort("sort values mismatch"); }
    print("stdlib_prop_stacking: stacked properties verified");
}
