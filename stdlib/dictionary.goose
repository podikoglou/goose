// The Goose standard library: `dictionary` (docs/stdlib.md).
// Open addressing with linear probing over a power-of-two slot array,
// hash(key) & mask, backward-shift deletion (no tombstones). Keys and
// values are fixed-size; strings are keyed as u8[:] slices into text the
// caller owns, or as inline u8[..k]. A user key type provides
// `fn hash(k: key) -> u64` (and `==`). A reference value is an optional
// one, plain or `in pool`: new slots hold default<V>(), which a
// non-optional reference has none of.
//
// Each slot keeps a tag: 0 when the slot is unused, else the low 31 bits of
// the key's hash with bit 31 set. A probe compares keys only where the tags
// agree, and while the table has at most 2^31 slots the tag holds the home
// slot, so growth and removal never hash a key again (a larger table hashes
// the keys it moves). The table doubles in place at 2/3 load.
//
// The slot array is grow-shrink so that growth can resize it in place
// through a reference (spec §5.2); as a consequence a reference obtained
// from get/get_or_insert, or a binder inside each, may not be in scope at
// the next insert, update, remove or clear (the checker says so).

import std;

struct dictionary_slot<K, V> { key: K, val: V, tag: u32 }
struct dictionary<K, V> { count: i64 = 0, slots: dictionary_slot<K, V>[>..<] = [] }

fn dict_tag(h: u64) -> u32 { (h as! u32) | 2147483648 }

// The slot holding key, or -1.
fn dict_probe<K, V>(d: dictionary<K, V>&, key: K) -> i64 {
    if d.count == 0 { return -1; }
    let h = hash(key);
    let tag = dict_tag(h);
    let mask = d.slots.len - 1;
    var i = (h & (mask as u64)) as i64;
    loop {
        let t = d.slots[i].tag;
        if t == tag {
            if d.slots[i].key == key { return i; }
        } else if t == 0 {
            return -1;
        }
        i = (i + 1) & mask;
    }
}

// The slot holding key, or else the unused slot where it goes, for a table
// that has one.
fn dict_slot<K, V>(d: dictionary<K, V>&, key: K, h: u64) -> i64 {
    let tag = dict_tag(h);
    let mask = d.slots.len - 1;
    var i = (h & (mask as u64)) as i64;
    loop {
        let t = d.slots[i].tag;
        if t == tag {
            if d.slots[i].key == key { return i; }
        } else if t == 0 {
            return i;
        }
        i = (i + 1) & mask;
    }
}

// Room for one more entry: the table starts at 8 slots and doubles at 2/3
// load. With its two calls dict_grow stays a function of its own rather than
// being inlined into each caller, which keeps the callers small, and the
// stack top that resize fills through stays in a register there
// (docs/implementation.md §6.10).
fn dict_room<K, V>(d: dictionary<K, V>&) {
    if d.slots.len == 0 {
        dict_grow(d, 8);
    } else if (d.count + 1) * 3 > d.slots.len * 2 {
        dict_grow(d, d.slots.len * 2);
    }
}

// Grows the table to cap slots, a power of two above its length, in place:
// the new slots start unused, and every entry is re-placed by a walk over the
// old slots in cyclic order from just after an unused one. Each entry then
// lands within a run of slots that have all been walked already, so no
// entry yet to be moved ever lies on a moved entry's probe path.
fn dict_grow<K, V>(d: dictionary<K, V>&, cap: i64) {
    let old = d.slots.len;
    d.slots.resize(cap, dictionary_slot<K, V> { default<K>(), default<V>(), 0 });
    if d.count == 0 { return; }
    let mask = cap - 1;
    var s = 0;
    while d.slots[s].tag != 0 { s += 1; }
    for k in 1..old {
        var p = s + k;
        if p >= old { p -= old; }
        let t = d.slots[p].tag;
        if t != 0 {
            var q = (t as i64) & mask;
            if mask >= 2147483648 { q = (hash(d.slots[p].key) & (mask as u64)) as i64; }
            let e = d.slots[p];
            d.slots[p].tag = 0;
            while d.slots[q].tag != 0 { q = (q + 1) & mask; }
            d.slots[q] = e;
        }
    }
}

// A reference to the value for key, or null.
fn get<K, V>(d: dictionary<K, V>&, key: K) -> V? {
    let i = dict_probe(d, key);
    if i < 0 { return null; }
    return d.slots[i].val;
}

fn contains<K, V>(d: dictionary<K, V>&, key: K) -> bool { dict_probe(d, key) >= 0 }

// Sets key to val; true if the key was new. Like get_or_insert and update,
// it makes room for the key before the one walk that finds it or the unused
// slot where it goes.
prop "insert-get roundtrip" for (k: i64), (v: i64) {
    var d = dictionary<i64, i64> {};
    insert(d, k, v);
    let p = get(d, k);
    p != null && p == v && contains(d, k) && d.count == 1
}
prop "value overwrite" for (k: i64), (v1: i64), (v2: i64) {
    var d = dictionary<i64, i64> {};
    insert(d, k, v1);
    let is_new = insert(d, k, v2);
    let p = get(d, k);
    !is_new && p != null && p == v2 && d.count == 1
}
fn insert<K, V>(d: dictionary<K, V>&, key: K, val: V) -> bool {
    dict_room(d);
    let h = hash(key);
    let i = dict_slot(d, key, h);
    if d.slots[i].tag != 0 {
        // The whole slot, since `=` into a reference V would write its
        // pointee (§3.8); the stored key stays.
        d.slots[i] = dictionary_slot<K, V> { d.slots[i].key, val, d.slots[i].tag };
        return false;
    }
    d.slots[i] = dictionary_slot<K, V> { key, val, dict_tag(h) };
    d.count += 1;
    return true;
}

// The value for key, inserted as v0 first if absent.
fn get_or_insert<K, V>(d: dictionary<K, V>&, key: K, v0: V) -> V& {
    dict_room(d);
    let h = hash(key);
    let i = dict_slot(d, key, h);
    if d.slots[i].tag == 0 {
        d.slots[i] = dictionary_slot<K, V> { key, v0, dict_tag(h) };
        d.count += 1;
    }
    return d.slots[i].val;
}

// F(val&) on the value for key, inserted as v0 first if absent.
fn update<K, V, F>(d: dictionary<K, V>&, key: K, v0: V) {
    dict_room(d);
    let h = hash(key);
    let i = dict_slot(d, key, h);
    if d.slots[i].tag == 0 {
        d.slots[i] = dictionary_slot<K, V> { key, v0, dict_tag(h) };
        d.count += 1;
    }
    F(&d.slots[i].val);
}

// Removes key; true if it was there.
prop "insertion followed by removal" for (k: i64), (v: i64) {
    var d = dictionary<i64, i64> {};
    insert(d, k, v);
    let removed = remove(d, k);
    removed && !contains(d, k) && get(d, k) == null && d.count == 0
}
prop "non-existent key removal" for (k: i64) {
    var d = dictionary<i64, i64> {};
    !remove(d, k) && d.count == 0
}
fn remove<K, V>(d: dictionary<K, V>&, key: K) -> bool {
    var i = dict_probe(d, key);
    if i < 0 { return false; }
    let mask = d.slots.len - 1;
    var j = i;
    loop {
        j = (j + 1) & mask;
        let t = d.slots[j].tag;
        if t == 0 { break; }
        var h = (t as i64) & mask;
        if mask >= 2147483648 { h = (hash(d.slots[j].key) & (mask as u64)) as i64; }
        // An entry whose home is not in the cyclic range (i, j] can move up
        // into the hole without leaving its probe sequence.
        if ((j - h) & mask) >= ((j - i) & mask) {
            d.slots[i] = d.slots[j];
            i = j;
        }
    }
    d.slots[i] = dictionary_slot<K, V> { default<K>(), default<V>(), 0 };
    d.count -= 1;
    return true;
}

prop "clear empties dictionary" for (k1: i64), (v1: i64), (k2: i64), (v2: i64) {
    var d = dictionary<i64, i64> {};
    insert(d, k1, v1);
    insert(d, k2, v2);
    clear(d);
    d.count == 0 && !contains(d, k1) && !contains(d, k2)
}
fn clear<K, V>(d: dictionary<K, V>&) {
    for &s in d.slots { s.tag = 0; }
    d.count = 0;
}

// Room for n entries without growing.
fn reserve<K, V>(d: dictionary<K, V>&, n: i64) {
    let need = max(next_pow2((n * 3 + 1) / 2), 8);
    if need > d.slots.len { dict_grow(d, need); }
}

// F(key, val&) for every entry, in no particular order.
fn each<K, V, F>(d: dictionary<K, V>&) {
    for &s in d.slots { if s.tag != 0 { F(s.key, &s.val); } }
}

fn len<K, V>(d: dictionary<K, V>&) -> i64 { d.count }

// --- set<T> ---

struct set_slot<T> { key: T, tag: u32 }
struct set<T> { count: i64 = 0, slots: set_slot<T>[>..<] = [] }

// The slot holding val, or -1.
fn set_probe<T>(s: set<T>&, val: T) -> i64 {
    if s.count == 0 { return -1; }
    let h = hash(val);
    let tag = dict_tag(h);
    let mask = s.slots.len - 1;
    var i = (h & (mask as u64)) as i64;
    loop {
        let t = s.slots[i].tag;
        if t == tag {
            if s.slots[i].key == val { return i; }
        } else if t == 0 {
            return -1;
        }
        i = (i + 1) & mask;
    }
}

// The slot holding val, or else the unused slot where it goes, for a table
// that has one.
fn set_find_slot<T>(s: set<T>&, val: T, h: u64) -> i64 {
    let tag = dict_tag(h);
    let mask = s.slots.len - 1;
    var i = (h & (mask as u64)) as i64;
    loop {
        let t = s.slots[i].tag;
        if t == tag {
            if s.slots[i].key == val { return i; }
        } else if t == 0 {
            return i;
        }
        i = (i + 1) & mask;
    }
}

// Room for one more entry: starts at 8 slots and doubles at 2/3 load.
fn set_room<T>(s: set<T>&) {
    if s.slots.len == 0 {
        set_grow(s, 8);
    } else if (s.count + 1) * 3 > s.slots.len * 2 {
        set_grow(s, s.slots.len * 2);
    }
}

// Grows the set to cap slots in place.
fn set_grow<T>(s: set<T>&, cap: i64) {
    let old = s.slots.len;
    s.slots.resize(cap, set_slot<T> { default<T>(), 0 });
    if s.count == 0 { return; }
    let mask = cap - 1;
    var st = 0;
    while s.slots[st].tag != 0 { st += 1; }
    for k in 1..old {
        var p = st + k;
        if p >= old { p -= old; }
        let t = s.slots[p].tag;
        if t != 0 {
            var q = (t as i64) & mask;
            if mask >= 2147483648 { q = (hash(s.slots[p].key) & (mask as u64)) as i64; }
            let e = s.slots[p];
            s.slots[p].tag = 0;
            while s.slots[q].tag != 0 { q = (q + 1) & mask; }
            s.slots[q] = e;
        }
    }
}

fn contains<T>(s: set<T>&, val: T) -> bool { set_probe(s, val) >= 0 }

// Inserts val into the set; returns true if newly inserted, false if already present.
fn insert<T>(s: set<T>&, val: T) -> bool {
    set_room(s);
    let h = hash(val);
    let i = set_find_slot(s, val, h);
    if s.slots[i].tag != 0 {
        return false;
    }
    s.slots[i] = set_slot<T> { val, dict_tag(h) };
    s.count += 1;
    return true;
}

// Removes val; returns true if present and removed, false if not found.
fn remove<T>(s: set<T>&, val: T) -> bool {
    var i = set_probe(s, val);
    if i < 0 { return false; }
    let mask = s.slots.len - 1;
    var j = i;
    loop {
        j = (j + 1) & mask;
        let t = s.slots[j].tag;
        if t == 0 { break; }
        var h = (t as i64) & mask;
        if mask >= 2147483648 { h = (hash(s.slots[j].key) & (mask as u64)) as i64; }
        if ((j - h) & mask) >= ((j - i) & mask) {
            s.slots[i] = s.slots[j];
            i = j;
        }
    }
    s.slots[i] = set_slot<T> { default<T>(), 0 };
    s.count -= 1;
    return true;
}

fn len<T>(s: set<T>&) -> i64 { s.count }

fn clear<T>(s: set<T>&) {
    for &slot in s.slots { slot.tag = 0; }
    s.count = 0;
}

// Room for n entries without growing.
fn reserve<T>(s: set<T>&, n: i64) {
    let need = max(next_pow2((n * 3 + 1) / 2), 8);
    if need > s.slots.len { set_grow(s, need); }
}

// F(val) for every entry, in no particular order.
fn each<T, F>(s: set<T>&) {
    for &slot in s.slots { if slot.tag != 0 { F(slot.key); } }
}
