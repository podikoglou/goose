// error: property variable 'MAX_RETRIES' shadows a module-level symbol of the same name
const MAX_RETRIES = 5;

prop for MAX_RETRIES {
    MAX_RETRIES <= 5
}
fn test() {}
fn main() {}
