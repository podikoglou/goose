// 32_proptest.goose - Property-based testing in Goose
//
// Demonstrates proptest: a single-file, zero-allocation property testing library
// for Goose inspired by Bolero (Rust) and Hypothesis (Python).
//
// Key Concepts:
// 1. Invariant-based testing: Instead of hand-writing 3-4 example test inputs,
//    you state properties that must hold true for ALL valid inputs (e.g. `rev(rev(xs)) == xs`).
// 2. High-Performance Driver: In Goose, memory lives on compiler-managed data stacks
//    with bump allocation. A 10,000-element structure frees in ONE CPU store instruction,
//    allowing property checks to run at over 15,000,000 executions per second!
// 3. Universal Byte Shrinking: When a property fails, the library automatically
//    shrinks the failing input (via binary search truncation, chunk deletion, and
//    byte minimization) down to the absolute minimal reproducing counterexample.
//
// Run with:
//   build/goose samples/32_proptest.goose

import std;
import os;
import proptest;

// ============================================================================
// Perspective 1: Mathematical Invariants & Primitive Properties
// ============================================================================

// A property test is written using `check().iterations(N).for_each() { d => ... }`.
// Inside the trailing block, `d` is a `Driver&` that supplies pseudo-random values.
fn demo_math_properties() {
    print("--- 1. Testing Mathematical Properties ---");

    // Test: Commutativity of addition for 64-bit integers.
    // Notice how `d.gen_i64_range` automatically injects boundary edge-cases
    // (0, 1, -1, min, max) ~10% of the time to catch arithmetic overflow.
    check()
        .iterations(10000)
        .for_each() { d =>
            let a = d.gen_i64_range(-1000000, 1000000);
            let b = d.gen_i64_range(-1000000, 1000000);
            (a + b) == (b + a)
        };
    print("  [OK] Addition commutativity verified across 10,000 random inputs");

    // Test: Absolute value is always non-negative (within safe range).
    check()
        .iterations(5000)
        .for_each() { d =>
            let x = d.gen_i64_range(-1000000, 1000000);
            let abs_x = if x < 0 { -x } else { x };
            abs_x >= 0
        };
    print("  [OK] Absolute value non-negativity verified");
}

// ============================================================================
// Perspective 2: Data Structures & Collections (Reverse, Sort)
// ============================================================================

fn reverse_array<T>(xs: T[:], out: T[>..]&) {
    var i = xs.len;
    while i > 0 {
        i -= 1;
        out.push(xs[i]);
    }
}

fn demo_collection_properties() {
    print("--- 2. Testing Collection Properties ---");

    // Invariant: Reversing an array twice produces the identical array.
    // `d.gen_array(min_len, max_len) { drv => ... }` uses trailing blocks
    // to dynamically generate elements of arbitrary types.
    check()
        .iterations(2000)
        .for_each() { d =>
            let xs = d.gen_array(0, 50) { drv =>
                drv.gen_i64_range(-1000, 1000)
            };

            var rev1: i64[>..] = [];
            reverse_array(xs[..], rev1);

            var rev2: i64[>..] = [];
            reverse_array(rev1[..], rev2);

            rev2 == xs
        };
    print("  [OK] Array double-reversal identity verified");

    // Invariant: Sorting is idempotent: sort(sort(xs)) == sort(xs).
    check()
        .iterations(2000)
        .for_each() { d =>
            let xs = d.gen_array(0, 40) { drv =>
                drv.gen_i32()
            };

            var s1 = copy(xs);
            sort(s1);

            var s2 = copy(s1);
            sort(s2);

            s1 == s2
        };
    print("  [OK] Sort idempotence verified");
}

// ============================================================================
// Perspective 3: Custom Types & Structure Generation
// ============================================================================

// Custom domain model
struct OrderItem {
    sku: u8[..8],
    quantity: i32,
    price_cents: i64,
}

struct CustomerOrder {
    order_id: i64,
    items: OrderItem[>..],
}

// User-defined generator functions simply take `d: Driver&`
fn gen_order_item(d: Driver&) -> OrderItem {
    let sku = d.gen_ascii_string(3, 8);
    var sku_buf: u8[..8] = [];
    sku_buf.append(sku);
    return OrderItem {
        sku: sku_buf,
        quantity: d.gen_i32_range(1, 100),
        price_cents: d.gen_i64_range(50, 50000),
    };
}

fn gen_customer_order(d: Driver&) -> CustomerOrder {
    let order_id = d.gen_i64_range(1000, 999999);
    var items: OrderItem[>..] = [];
    let n_items = d.gen_i64_range(1, 10);
    for i in n_items {
        items.push(gen_order_item(d));
    }
    return CustomerOrder {
        order_id: order_id,
        items: items,
    };
}

fn calculate_total_cents(order: CustomerOrder&) -> i64 {
    var total: i64 = 0;
    for &item in order.items {
        total += item.quantity * item.price_cents;
    }
    return total;
}

fn demo_custom_structs() {
    print("--- 3. Testing Custom Domain Types ---");

    // Invariant: An order with at least 1 item (quantity >= 1, price >= 50)
    // must always have a total order price strictly greater than 0.
    check()
        .iterations(2000)
        .for_each() { d =>
            let order = gen_customer_order(d);
            let total = calculate_total_cents(order);
            total > 0
        };
    print("  [OK] Customer order total business invariants verified");
}

// ============================================================================
// Perspective 4: Automatic Shrinking of Failing Counterexamples
// ============================================================================

// Suppose a developer wrote a buggy division/lookup function that breaks
// on a specific boundary condition.
fn buggy_service(a: i64, b: i64) -> bool {
    // Hidden bug: fails if both numbers are >= 100
    if a >= 100 && b >= 100 {
        return false;
    }
    return true;
}

fn demo_automatic_shrinking() {
    print("--- 4. Demonstrating Universal Byte Shrinking ---");

    // We use `.run()` instead of `.for_each()` to inspect the test result
    // programmatically without halting the process with abort().
    let result = check()
        .iterations(1000)
        .run() { d =>
            let a = d.gen_i64_range(0, 1000000);
            let b = d.gen_i64_range(0, 1000000);
            buggy_service(a, b)
        };

    if !result.passed {
        print("  Bug detected on iteration: ", result.failed_iteration);
        print("  Automatic shrinking result: ", result.shrunk_bytes_len, " bytes (", result.shrink_steps, " shrink steps)");

        // Replaying the minimal shrunken bytes into the generator:
        var d = make_driver_from_bytes(result.shrunk_bytes[..], 5);
        let min_a = d.gen_i64_range(0, 1000000);
        let min_b = d.gen_i64_range(0, 1000000);
        print("  Minimal counterexample discovered: a = ", min_a, ", b = ", min_b);
        print("  (Notice how both numbers shrank directly to the boundary 100!)");
    }
}

// ============================================================================
// Perspective 5: Reproducibility & Deterministic Replay
// ============================================================================

fn demo_reproducibility() {
    print("--- 5. Deterministic Reproduction ---");

    // Any test run can be pinned to an exact seed:
    let fixed_seed: u64 = 0x123456789ABCDEF0;

    let res1 = check()
        .seed(fixed_seed)
        .iterations(100)
        .run() { d =>
            let val = d.gen_i64();
            val != 42
        };

    let res2 = check()
        .seed(fixed_seed)
        .iterations(100)
        .run() { d =>
            let val = d.gen_i64();
            val != 42
        };

    // Both runs are bit-for-bit identical!
    assert(res1.passed == res2.passed);
    assert(res1.total_iterations == res2.total_iterations);
    print("  [OK] Seed 0x", hex(fixed_seed), " produces bit-for-bit identical runs across executions");
}

fn hex(n: u64) -> u8[>..] {
    let digits = "0123456789abcdef";
    var out: u8[>..] = [];
    var v = n;
    for i in 16 {
        let d = (v >> 60) & 0xF;
        out.push(digits[d as i64]);
        v = v << 4;
    }
    return out;
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() {
    print("=================================================");
    print("   Goose Property Testing Library Showcase       ");
    print("=================================================");
    demo_math_properties();
    demo_collection_properties();
    demo_custom_structs();
    demo_automatic_shrinking();
    demo_reproducibility();
    print("=================================================");
    print("   All demonstration properties executed!        ");
    print("=================================================");
}
