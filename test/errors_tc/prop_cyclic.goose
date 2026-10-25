// error: cyclic constraint between property variables
prop for i, j where i < j, j < i {
    i == j
}
fn test() {}
fn main() {}
