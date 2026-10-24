// Multi-variable comma assignment desugaring and roundtrip syntax coverage.
fn f(x: i64) -> i64 { x * 2 }

fn main() {
    var a = 1;
    var b = 2;
    a, b = b, a;

    var x = 10;
    var y = 20;
    var z = 30;
    x, y, z = f(x), f(y) + 1, f(z) - 2;

    var xs = [1, 2, 3];
    var i = 0;
    var j = 2;
    xs[i], xs[j] = xs[j], xs[i];

    print(a, " ", b);
    print(x, " ", y, " ", z);
    print(xs[0], " ", xs[1], " ", xs[2]);
}
