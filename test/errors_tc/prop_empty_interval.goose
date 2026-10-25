// error: unsatisfiable constraint on 'x': interval is empty
prop for x where x > 10, x < 5 {
    x > 0
}
fn test() {}
fn main() {}
