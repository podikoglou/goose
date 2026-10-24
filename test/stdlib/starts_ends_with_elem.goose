// runtime-debug: single-element and slice starts_with and ends_with
import std;

struct Item {
    id: i64,
    tag: u8,
}

fn test_strings() {
    print("--- strings ---");
    let s = "hello";
    print(starts_with(s, 'h'), " ", starts_with(s, 'e'));
    print(ends_with(s, 'o'), " ", ends_with(s, 'l'));
    print(s.starts_with('h'), " ", s.ends_with('o'));

    let empty = "";
    print(starts_with(empty, 'a'), " ", ends_with(empty, 'a'));
    print(empty.starts_with('x'), " ", empty.ends_with('x'));

    let single = "a";
    print(single.starts_with('a'), " ", single.ends_with('a'));
    print(single.starts_with('b'), " ", single.ends_with('b'));

    // Existing slice overloads on string
    print(starts_with("hello", "he"), " ", starts_with("hello", "lo"));
    print(ends_with("hello", "lo"), " ", ends_with("hello", "he"));
    print("hello".starts_with("hello"), " ", "hello".ends_with("hello"));
    print("hello".starts_with(""), " ", "hello".ends_with(""));
    print("".starts_with(""), " ", "".ends_with(""));
}

fn test_ints() {
    print("--- ints ---");
    let xs = [10, 20, 30];
    print(starts_with(xs[..], 10), " ", starts_with(xs[..], 20));
    print(ends_with(xs[..], 30), " ", ends_with(xs[..], 20));
    print(xs[..].starts_with(10), " ", xs[..].ends_with(30));

    let empty: i64[] = [];
    print(empty[..].starts_with(10), " ", empty[..].ends_with(10));

    let single = [42];
    print(single[..].starts_with(42), " ", single[..].ends_with(42));
    print(single[..].starts_with(99), " ", single[..].ends_with(99));

    // Existing slice overload
    let p1 = [10, 20];
    let p2 = [20, 30];
    print(xs[..].starts_with(p1[..]), " ", xs[..].ends_with(p2[..]));
    print(xs[..].starts_with(p2[..]), " ", xs[..].ends_with(p1[..]));
}

fn test_floats() {
    print("--- floats ---");
    let fs = [1.5, 2.5, 3.5];
    print(starts_with(fs[..], 1.5), " ", starts_with(fs[..], 2.0));
    print(ends_with(fs[..], 3.5), " ", ends_with(fs[..], 2.5));
    print(fs[..].starts_with(1.5), " ", fs[..].ends_with(3.5));

    let empty: f64[] = [];
    print(empty[..].starts_with(1.5), " ", empty[..].ends_with(1.5));

    let pref = [1.5, 2.5];
    print(fs[..].starts_with(pref[..]), " ", fs[..].ends_with(pref[..]));
}

fn test_structs() {
    print("--- structs ---");
    let a = Item { id: 1, tag: 'a' };
    let b = Item { id: 2, tag: 'b' };
    let c = Item { id: 3, tag: 'c' };

    let items = [a, b, c];
    print(starts_with(items[..], a), " ", starts_with(items[..], b));
    print(ends_with(items[..], c), " ", ends_with(items[..], b));
    print(items[..].starts_with(a), " ", items[..].ends_with(c));

    let empty: Item[] = [];
    print(empty[..].starts_with(a), " ", empty[..].ends_with(a));

    let single = [b];
    print(single[..].starts_with(b), " ", single[..].ends_with(b));
    print(single[..].starts_with(a), " ", single[..].ends_with(c));

    // Existing slice overload
    let sub = [a, b];
    print(items[..].starts_with(sub[..]), " ", items[..].ends_with(sub[..]));
}

fn main() {
    test_strings();
    test_ints();
    test_floats();
    test_structs();
}
