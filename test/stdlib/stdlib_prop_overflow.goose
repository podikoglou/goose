// Property verification test fixture: Integer overflow counterexample discovery and replay
import std;

prop "strictly monotonic" for i, j where i in 2..=95, j in (i + 1)..=95 {
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
    let f92 = fib(92);
    let f93 = fib(93);
    print("fib(92) = ", f92, " fib(93) = ", f93);
    if f93 >= 0 {
        abort("expected fib(93) to wrap negative in 64-bit signed integer arithmetic");
    }
    print("stdlib_prop_overflow: fib(93) negative overflow demonstrated");
}
