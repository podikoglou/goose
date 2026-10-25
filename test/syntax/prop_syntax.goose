// parse-only
// Syntax coverage for top-level declarative properties (prop).

prop for i where i in 6..=90 {
    fib(i) > i
}
fn fib(n: i64) -> i64 {
    n
}

prop "idempotent" for xs {
    sort(sort(xs)) == sort(xs)
}
prop "preserves length" for xs with (iterations = 5000, timeout_ms = 1000) {
    sort(xs).len == xs.len
}
fn sort(xs: const i64[:]) -> i64[>..] {
    let res: i64[>..] = [];
    res
}

prop "typed quantifier" for (data: const u8[:]) where data.len > 0 with (max_len = 8192) {
    data.len > 0
}
struct S {
    x: i64,
}

prop "monotonic" for i, j, k where i in 2..=90, j in (i + 1)..=90, k in (j + 1)..=90 {
    (fib(i) < fib(j)) && (fib(j) < fib(k))
}
fn dummy(x: i64) -> i64 { x }
