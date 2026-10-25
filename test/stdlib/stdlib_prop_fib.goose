// Property verification test fixture: Fibonacci intervals and monotonicity
import std;

prop "overtake index" for i where i in 6..=90 {
    fib(i) > i
}

prop "strictly monotonic" for i, j where i in 2..=90, j in (i + 1)..=90 {
    fib(i) < fib(j)
}
fn fib(n: i64) -> i64 {
    var a: i64 = 0;
    var b: i64 = 1;
    for _ in n {
        let t = a + b;
        a = b;
        b = t;
    }
    a
}

fn main() {
    if fib(0) != 0 || fib(1) != 1 { abort("fib base case failed"); }
    if fib(6) != 8 { abort("fib(6) != 8"); }
    if fib(6) <= 6 { abort("fib(6) should be > 6"); }
    if fib(90) != 2880067194370816120 { abort("fib(90) value mismatch"); }
    if fib(10) >= fib(20) { abort("monotonicity failed"); }
    print("stdlib_prop_fib: fib interval and monotonicity properties verified");
}
