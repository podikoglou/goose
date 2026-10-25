// error: variable 'x' in runtime constraint has an unbounded domain; hint: add an explicit interval bound in 'where', e.g., 'x in 1..=1000'
prop for x, y where x + y < 1000 {
    (x + y) > x
}
fn test() {}
fn main() {}
