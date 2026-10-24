// runtime-debug: stdlib/dictionary.goose: first-class set<T>
import dictionary;

struct key { a: i64, b: i64 }
fn hash(k: key) -> u64 { hash_combine(hash(k.a), hash(k.b)) }

// Struct with constant hash to force probe collisions and test backward-shift deletion
struct coll { id: i64 }
fn hash(c: coll) -> u64 { 2 }

// Struct with hash that lands on the last slot of an 8-slot table to test wrap-around
struct wrap_coll { id: i64 }
fn hash(w: wrap_coll) -> u64 { 7 }

fn main() {
    // 1. Basic insertions, duplicates, len and contains
    var s = set<i64> {};
    print(s.insert(10), " ", s.insert(20), " ", s.insert(10)); // true true false
    print(s.len(), " ", s.contains(10), " ", s.contains(30));  // 2 true false

    // 2. Removals
    print(s.remove(10), " ", s.remove(10), " ", s.contains(10), " ", s.len()); // true false false 1
    print(s.remove(20), " ", s.len()); // true 0

    // 3. Backward-shift deletion within a cluster (same home slot)
    var cs = set<coll> {};
    for i in 1..6 {
        cs.insert(coll { i });
    }
    print(cs.len()); // 5
    // Remove the middle element (coll{3})
    print(cs.remove(coll { 3 })); // true
    print(cs.len()); // 4
    // Ensure all other elements in the cluster are preserved and reachable
    print(cs.contains(coll { 1 }), " ", cs.contains(coll { 2 }), " ",
          cs.contains(coll { 3 }), " ", cs.contains(coll { 4 }), " ",
          cs.contains(coll { 5 })); // true true false true true
    // Remove the head of the cluster (coll{1})
    print(cs.remove(coll { 1 })); // true
    print(cs.contains(coll { 1 }), " ", cs.contains(coll { 2 }), " ",
          cs.contains(coll { 4 }), " ", cs.contains(coll { 5 })); // false true true true
    // Remove remaining elements
    print(cs.remove(coll { 5 }), " ", cs.remove(coll { 2 }), " ", cs.remove(coll { 4 })); // true true true
    print(cs.len()); // 0

    // 4. Wrap-around clustering and backward-shift deletion across slot 0 boundary
    var ws = set<wrap_coll> {};
    for i in 1..5 {
        ws.insert(wrap_coll { i });
    }
    print(ws.len()); // 4
    // Remove element at boundary
    print(ws.remove(wrap_coll { 2 })); // true
    print(ws.contains(wrap_coll { 1 }), " ", ws.contains(wrap_coll { 2 }), " ",
          ws.contains(wrap_coll { 3 }), " ", ws.contains(wrap_coll { 4 })); // true false true true

    // 5. Growth / rehashing under load (inserting 1000 elements, removing half)
    var big = set<i64> {};
    for i in 1000 {
        big.insert(i * 3);
    }
    print(big.len()); // 1000
    var all_present = true;
    for i in 1000 {
        if !big.contains(i * 3) { all_present = false; }
    }
    print(all_present); // true

    // Remove even indices
    for i in 500 {
        big.remove(i * 6);
    }
    print(big.len()); // 500
    var check_evens_odds = true;
    for i in 1000 {
        let expected = (i % 2 == 1);
        if big.contains(i * 3) != expected { check_evens_odds = false; }
    }
    print(check_evens_odds); // true

    // 6. Clear and reserve
    big.clear();
    print(big.len(), " ", big.contains(3)); // 0 false
    big.reserve(100);
    print(big.slots.len >= 150, " ", big.len()); // true 0

    // 7. Strings (const u8[:])
    var str_set = set<const u8[:]> {};
    print(str_set.insert("alpha"), " ", str_set.insert("beta"), " ", str_set.insert("alpha")); // true true false
    print(str_set.len(), " ", str_set.contains("alpha"), " ", str_set.contains("gamma")); // 2 true false
    print(str_set.remove("alpha"), " ", str_set.len(), " ", str_set.contains("alpha")); // true 1 false

    // 8. Custom struct keys
    var k_set = set<key> {};
    k_set.insert(key { 1, 2 });
    k_set.insert(key { 3, 4 });
    k_set.insert(key { 1, 2 });
    print(k_set.len(), " ", k_set.contains(key { 1, 2 }), " ", k_set.contains(key { 2, 1 })); // 2 true false
    print(k_set.remove(key { 1, 2 }), " ", k_set.len()); // true 1

    // 9. Each iteration
    var iter_set = set<i64> {};
    iter_set.insert(10);
    iter_set.insert(20);
    iter_set.insert(30);
    var sum = 0;
    iter_set.each() { val => sum += val; };
    print(sum); // 60

    // 10. Dictionary symmetry: len()
    var dict = dictionary<const u8[:], i64> {};
    dict.insert("a", 1);
    dict.insert("b", 2);
    print(dict.len(), " ", len(dict)); // 2 2
}
