import std;

struct Point {
    x: i64,
    y: i64,
}

struct Node {
    id: i64,
    label: const u8[:],
}

fn test_ints() {
    var r = rng { 42 };
    let ints = [10, 20, 30, 40, 50];

    // Test with fixed seed
    let c1 = choose(ints, r);
    let c2 = choose(ints, r);
    let c3 = choose(ints, r);
    print("ints: ", c1, " ", c2, " ", c3);

    // Single-element slice
    let single = [999];
    print("single int: ", choose(single, r));

    // UFCS
    let c_ufcs = ints.choose(r);
    print("ufcs int: ", c_ufcs);

    // Distribution check: all elements hit eventually
    var counts = [0, 0, 0, 0, 0];
    for _ in 500 {
        let v = ints.choose(r);
        var found = false;
        for i in ints.len {
            if ints[i] == v {
                counts[i] += 1;
                found = true;
                break;
            }
        }
        assert(found);
    }
    var all_hit = true;
    for c in counts {
        if c == 0 { all_hit = false; }
    }
    print("all int elements hit: ", all_hit);
}

fn test_strings() {
    var r = rng { 42 };

    // String literal coercion to const u8[:]
    let letters = "abcdef";
    let ch1 = choose(letters, r);
    let ch2 = choose("xyz", r);
    let ch_single = choose("Q", r);
    print("string chars: ", ch1 == 'b', " ", ch2 == 'y', " ", ch_single == 'Q');
    print("contains: ", contains(letters, ch1), " ", contains("xyz", ch2));

    // Slice of strings
    let words = ["apple", "banana", "cherry", "date"];
    let w1 = choose(words, r);
    let w2 = words.choose(r);
    print("words: ", w1, " ", w2);

    // Single word slice
    let single_word = ["goose"];
    print("single word: ", choose(single_word, r));
}

fn test_structs() {
    var r = rng { 42 };

    let pts = [Point { 1, 10 }, Point { 2, 20 }, Point { 3, 30 }];
    let p1 = choose(pts, r);
    let p2 = pts.choose(r);
    print("points: (", p1.x, ",", p1.y, ") (", p2.x, ",", p2.y, ")");

    let nodes = [Node { 101, "first" }, Node { 202, "second" }];
    let n1 = choose(nodes, r);
    print("node: ", n1.id, " ", n1.label);
}

fn test_other_types() {
    var r = rng { 42 };

    let bools = [true, false];
    let b = choose(bools, r);
    print("bool: ", b);

    let flts = [1.25, 2.5, 5.0];
    let f = flts.choose(r);
    print("flt: ", f);
}

fn main() {
    test_ints();
    test_strings();
    test_structs();
    test_other_types();
}
