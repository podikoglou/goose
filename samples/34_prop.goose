// 34_prop.goose - Declarative Property Verification in Goose (`prop`)
//
// Demonstrates Goose's first-class top-level declarative property verification:
// 1. Hygienic Quantification: State properties directly above the functions they verify.
//    Free variables are inferred from adjacent function signatures or declared in `for`.
// 2. Pragmatic Constraint Solving:
//    - Tier 1: Static intervals (`i in 6..=90`) narrow generators with 0% discard rate.
//    - Tier 2: Relational dependencies (`j in (i + 1)..=90`) with reverse-topological bound tightening.
//    - Tier 3: Multi-variable linear constraints (`x + y < 1000`) lowered to runtime `assume()` filters.
// 3. Stacking: Attach multiple independent verification properties above a single function.
// 4. Data-Stack Slices: Slices (`const T[:]`) automatically synthesize bump-stack backed arrays.
//
// Run with:
//   build/goose test samples/34_prop.goose          # Run all declarative properties
//   build/goose test samples/34_prop.goose --target fib::strictly_monotonic
//   build/goose samples/34_prop.goose               # Compile & run standalone sample
import std;

// ============================================================================
// Section 1: Interval Narrowing & Relational Dependencies
// ============================================================================

// Fib overtake index: F_n > n holds for n in [6, 90] within 64-bit limits
prop "overtake index" for i where i in 6..=90 {
    fib(i) > i
}

// Fib monotonicity: F_i < F_j for 2 <= i < j <= 90
// Notice reverse-topological tightening: j in (i + 1)..=90 tightens i's domain to [2, 89]!
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

// ============================================================================
// Section 2: Property Stacking & Inferred Slice Parameters
// ============================================================================

// Multiple properties stacked above a single function:
// 'xs' type is automatically deduced as `const i64[:]` from fn sort!
prop "idempotent" for xs {
    sort(sort(xs)) == sort(xs)
}

prop "preserves length" for xs with (iterations = 1000) {
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

// ============================================================================
// Section 3: Algebraic Identities on Dynamic Slices
// ============================================================================

prop "algebraic identity" for (xs: const i64[:]) where xs.len in 1..=64 {
    reverse(reverse(xs)) == xs
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

// ============================================================================
// Section 4: Tier 3 Multi-Variable Assumption Filtering
// ============================================================================

prop "linear sum" for x, y where x in 1..=1000, y in 1..=1000, x + y < 1000 {
    (x + y) > x && (x + y) > y
}
fn add(a: i64, b: i64) -> i64 {
    a + b
}

// ============================================================================
// Main Execution (Standalone Sample Demonstration)
// ============================================================================

fn main() {
    print("--- Declarative Property Verification (`prop`) ---");

    // 1. Fibonacci invariant checks
    print("1. Fibonacci properties:");
    print("   fib(6) = ", fib(6), " (> 6: ", fib(6) > 6, ")");
    print("   fib(20) = ", fib(20), ", fib(21) = ", fib(21), " (monotonic: ", fib(20) < fib(21), ")");

    // 2. Sorting invariants
    print("2. Sorting properties:");
    let unsorted: i64[] = [9, 3, 7, 1, 5, 2];
    let sorted1 = sort(unsorted[..]);
    let sorted2 = sort(sorted1[..]);
    print("   input:      ", unsorted[..]);
    print("   sorted:     ", sorted1[..]);
    print("   idempotent: ", sorted1 == sorted2);
    print("   len equal:  ", sorted1.len == unsorted.len);

    // 3. Reverse involution
    print("3. Reverse involution:");
    let sample: i64[] = [10, 20, 30, 40, 50];
    let rev = reverse(sample[..]);
    let orig = reverse(rev[..]);
    print("   original:   ", sample[..]);
    print("   reversed:   ", rev[..]);
    print("   restored:   ", orig[..]);
    print("   identity:   ", orig == sample[..]);

    // 4. Linear bounds
    print("4. Linear constraints:");
    print("   add(200, 300) = ", add(200, 300), " (< 1000: ", add(200, 300) < 1000, ")");

    print("34_prop: all declarative property examples demonstrated successfully");
}
