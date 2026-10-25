// Property verification test fixture: Slice views and dynamic collections
import std;

prop "algebraic identity" for (xs: const i64[:]) where xs.len in 1..=64 {
    reverse(reverse(xs)) == xs
}

prop "bounded slice" for (data: const i64[:]) where data.len in 1..=64 {
    data.len >= 1 && data.len <= 64
}
fn reverse(xs: const i64[:]) -> i64[>..] {
    var out: i64[>..] = [];
    var i = xs.len;
    while i > 0 {
        i -= 1;
        out.push(xs[i]);
    }
    out
}

fn reverse(xs: i64[>..]) -> i64[>..] {
    reverse(xs[..])
}

fn main() {
    let sample: i64[] = [10, 20, 30, 40];
    let rev = reverse(sample[..]);
    let orig = reverse(rev[..]);
    if orig != sample[..] {
        abort("reverse identity failed");
    }
    print("stdlib_prop_slice: slice views and algebraic identity verified");
}
