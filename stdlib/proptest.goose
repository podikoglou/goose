// proptest.goose — Property-based testing and structure-aware fuzzing (docs/stdlib.md).
//
// Overview:
//   proptest provides automated invariant testing and structure-aware fuzzing
//   inspired by Bolero (Rust) and Hypothesis (Python), tailored for Goose's
//   zero-allocation data-stack memory architecture.
//
// Core Components:
//   1. Driver: The central source of entropy. Produces typed values either from
//      an ultra-fast inlined SplitMix64 PRNG (proptest mode, >50M values/sec)
//      or from a byte buffer (replay, mutation fuzzing, and shrinking).
//   2. Generators: Typed generators for primitives (u8..u64, i8..i64), floats,
//      booleans, strings, arrays, and sum-type variants, equipped with smart
//      boundary biasing (e.g. 0, 1, -1, NaN, extremes).
//   3. Universal Byte Shrinker: A 4-stage reduction engine (suffix truncation,
//      power-of-two chunk deletion, per-byte binary minimization toward 0,
//      and bit clearing) that shrinks any failing input to its minimal form.
//   4. In-Process Havoc Fuzzer: Mutation-based fuzzer maintaining an in-memory
//      corpus with bit flips, byte overwrites, chunk copies, and integer splices.
//   5. Contained Isolation: Traps runtime aborts and assertions in worker
//      threads using `thread_spawn_contained` and shrinks crashing inputs safely.

namespace proptest;

import std;
import os;

// Configuration for a property-based test or fuzzing campaign.
struct Config {
    opt_iterations:     i64 = 0,
    opt_seed:           u64 = 0,
    opt_max_len:        i64 = 0,
    opt_max_depth:      i32 = 0,
    opt_verbose:        bool = false,
    opt_shrink:         bool = true,
    opt_shrink_steps:   i64 = 5000,
    opt_shrink_time_ms: i64 = 2000,
    opt_fuzz:           bool = false,
    opt_timeout_ms:     i64 = 0,
    opt_corpus_size:    i64 = 64,
    opt_save_crashes:   bool = false,
    opt_crash_file:     const u8[:] = "",
    opt_has_replay:     bool = false,
    opt_replay_file:    const u8[:] = "",
    opt_replay_bytes:   const u8[:] = "",
    opt_fuzz_source_file: const u8[:] = "", // set by CLI harness: the .goose source file
    opt_fuzz_target_name: const u8[:] = "", // set by CLI harness: the fuzz target function name
    opt_max_discards:   i64 = 0,            // maximum inputs to discard via assume() before giving up
}

type ::Config = proptest::Config;

// Create a Config with standard defaults.
fn check() -> Config { Config { .. } }
fn ::check() -> proptest::Config { proptest::check() }

// Fluent configuration modifiers.
fn ::iterations(var c: Config, n: i64) -> Config        { c.opt_iterations = n; c }
fn ::seed(var c: Config, s: u64) -> Config              { c.opt_seed = s; c }
fn ::max_len(var c: Config, n: i64) -> Config           { c.opt_max_len = n; c }
fn ::max_depth(var c: Config, d: i32) -> Config         { c.opt_max_depth = d; c }
fn ::verbose(var c: Config) -> Config                   { c.opt_verbose = true; c }
fn ::verbose(var c: Config, v: bool) -> Config          { c.opt_verbose = v; c }
fn ::shrink(var c: Config, v: bool = true) -> Config    { c.opt_shrink = v; c }
fn ::no_shrink(var c: Config) -> Config                 { c.opt_shrink = false; c }
fn ::shrink_steps(var c: Config, n: i64) -> Config      { c.opt_shrink_steps = n; c }
fn ::shrink_time_ms(var c: Config, ms: i64) -> Config   { c.opt_shrink_time_ms = ms; c }
fn ::fuzz(var c: Config) -> Config                      { c.opt_fuzz = true; c }
fn ::fuzz(var c: Config, v: bool) -> Config             { c.opt_fuzz = v; c }
fn ::timeout_ms(var c: Config, ms: i64) -> Config       { c.opt_timeout_ms = ms; c }
fn ::corpus_size(var c: Config, n: i64) -> Config       { c.opt_corpus_size = n; c }
fn ::save_crashes(var c: Config) -> Config              { c.opt_save_crashes = true; c }
fn ::save_crashes(var c: Config, v: bool) -> Config     { c.opt_save_crashes = v; c }
fn ::crash_file(var c: Config, path: const u8[:]) -> Config {
    c.opt_crash_file = path;
    c.opt_save_crashes = true;
    c
}
fn ::replay(var c: Config, path: const u8[:]) -> Config {
    c.opt_replay_file = path;
    c.opt_has_replay = true;
    c
}
fn ::replay_bytes(var c: Config, raw: const u8[:]) -> Config {
    c.opt_replay_bytes = raw;
    c.opt_has_replay = true;
    c
}
fn ::fuzz_source_file(var c: Config, path: const u8[:]) -> Config {
    c.opt_fuzz_source_file = path; c
}
fn ::fuzz_target_name(var c: Config, name: const u8[:]) -> Config {
    c.opt_fuzz_target_name = name; c
}
fn ::max_discards(var c: Config, n: i64) -> Config {
    c.opt_max_discards = n; c
}

// Namespaced mirrors
fn iterations(var c: Config, n: i64) -> Config        { ::iterations(c, n) }
fn seed(var c: Config, s: u64) -> Config              { ::seed(c, s) }
fn max_len(var c: Config, n: i64) -> Config           { ::max_len(c, n) }
fn max_depth(var c: Config, d: i32) -> Config         { ::max_depth(c, d) }
fn verbose(var c: Config) -> Config                   { ::verbose(c) }
fn verbose(var c: Config, v: bool) -> Config          { ::verbose(c, v) }
fn shrink(var c: Config, v: bool = true) -> Config    { ::shrink(c, v) }
fn no_shrink(var c: Config) -> Config                 { ::no_shrink(c) }
fn shrink_steps(var c: Config, n: i64) -> Config      { ::shrink_steps(c, n) }
fn shrink_time_ms(var c: Config, ms: i64) -> Config   { ::shrink_time_ms(c, ms) }
fn fuzz(var c: Config) -> Config                      { ::fuzz(c) }
fn fuzz(var c: Config, v: bool) -> Config             { ::fuzz(c, v) }
fn timeout_ms(var c: Config, ms: i64) -> Config       { ::timeout_ms(c, ms) }
fn corpus_size(var c: Config, n: i64) -> Config       { ::corpus_size(c, n) }
fn save_crashes(var c: Config) -> Config              { ::save_crashes(c) }
fn save_crashes(var c: Config, v: bool) -> Config     { ::save_crashes(c, v) }
fn crash_file(var c: Config, path: const u8[:]) -> Config { ::crash_file(c, path) }
fn replay(var c: Config, path: const u8[:]) -> Config { ::replay(c, path) }
fn replay_bytes(var c: Config, raw: const u8[:]) -> Config { ::replay_bytes(c, raw) }
fn fuzz_source_file(var c: Config, path: const u8[:]) -> Config { ::fuzz_source_file(c, path) }
fn fuzz_target_name(var c: Config, name: const u8[:]) -> Config { ::fuzz_target_name(c, name) }
fn max_discards(var c: Config, n: i64) -> Config { ::max_discards(c, n) }

// Queries on Config.
fn ::is_replay(c: Config) -> bool                     { c.opt_has_replay }
fn ::replay_file_path(c: Config) -> const u8[:]       { c.opt_replay_file }
fn ::crash_file_path(c: Config) -> const u8[:] {
    if c.opt_crash_file.len > 0 { c.opt_crash_file } else { "crash.bin" }
}
fn ::should_save_crashes(c: Config) -> bool           { c.opt_save_crashes || c.opt_crash_file.len > 0 }
fn ::iterations_or_default(c: Config) -> i64 {
    if c.opt_iterations > 0 { c.opt_iterations } else if c.opt_fuzz { 0 } else { 1000 }
}
fn ::seed_or_default(c: Config) -> u64 {
    if c.opt_seed != 0 { c.opt_seed } else { random_seed() | 1 }
}
fn ::max_len_or_default(c: Config) -> i64             { if c.opt_max_len > 0 { c.opt_max_len } else { 4096 } }
fn ::max_depth_or_default(c: Config) -> i32           { if c.opt_max_depth > 0 { c.opt_max_depth } else { 5 } }
fn ::has_seed(c: Config) -> bool                      { c.opt_seed != 0 }
fn ::shrink_steps_or_default(c: Config) -> i64        { if c.opt_shrink_steps > 0 { c.opt_shrink_steps } else { 5000 } }
fn ::shrink_time_ms_or_default(c: Config) -> i64      { if c.opt_shrink_time_ms > 0 { c.opt_shrink_time_ms } else { 2000 } }
fn ::is_fuzz(c: Config) -> bool                       { c.opt_fuzz }
fn ::timeout_ms_or_default(c: Config) -> i64          { if c.opt_timeout_ms > 0 { c.opt_timeout_ms } else { 0 } }
fn ::corpus_size_or_default(c: Config) -> i64         { if c.opt_corpus_size > 0 { c.opt_corpus_size } else { 64 } }
fn ::max_discards_or_default(c: Config) -> i64 {
    if c.opt_max_discards > 0 {
        c.opt_max_discards
    } else {
        let n = iterations_or_default(c);
        if n < 100 { 1000 } else { n * 10 }
    }
}

// ---- Driver ----------------------------------------------------------------

// Driver provides deterministic entropy to generators either from an inlined
// SplitMix64 PRNG or a byte slice. If a byte slice is exhausted, it falls
// through to PRNG entropy without out-of-bounds errors.
struct Driver {
    prng:           rng,
    buf:            const u8[:],
    has_buf:        bool,
    cursor:         i64,
    depth:          i32,
    max_depth:      i32,
    iteration_seed: u64,
    record_mode:    bool,
    exhausted:      bool,
    assumed_false:  bool,
    recorded:       u8[>..],
}

type ::Driver = proptest::Driver;

// Construct a driver in PRNG mode.
fn driver(iteration_seed: u64 = 0, max_depth: i32 = 5) -> Driver {
    let s = if iteration_seed != 0 { iteration_seed } else { 1 };
    Driver {
        prng:           rng { s },
        buf:            ""[..0],
        has_buf:        false,
        cursor:         0,
        depth:          0,
        max_depth:      max_depth,
        iteration_seed: s,
        record_mode:    false,
        exhausted:      false,
        assumed_false:  false,
        recorded:       [],
    }
}
fn ::driver(iteration_seed: u64 = 0, max_depth: i32 = 5) -> proptest::Driver {
    proptest::driver(iteration_seed, max_depth)
}

// Construct a driver in recording mode.
fn recording_driver(iteration_seed: u64 = 0, max_depth: i32 = 5) -> Driver {
    let s = if iteration_seed != 0 { iteration_seed } else { 1 };
    Driver {
        prng:           rng { s },
        buf:            ""[..0],
        has_buf:        false,
        cursor:         0,
        depth:          0,
        max_depth:      max_depth,
        iteration_seed: s,
        record_mode:    true,
        exhausted:      false,
        assumed_false:  false,
        recorded:       [],
    }
}
fn ::recording_driver(iteration_seed: u64 = 0, max_depth: i32 = 5) -> proptest::Driver {
    proptest::recording_driver(iteration_seed, max_depth)
}

// Construct a driver reading from a byte buffer.
fn driver_from_bytes(bytes: const u8[:], max_depth: i32 = 5) -> Driver {
    Driver {
        prng:           rng { s: 1 },
        buf:            bytes,
        has_buf:        true,
        cursor:         0,
        depth:          0,
        max_depth:      max_depth,
        iteration_seed: 0,
        record_mode:    false,
        exhausted:      false,
        assumed_false:  false,
        recorded:       [],
    }
}
fn ::driver_from_bytes(bytes: const u8[:], max_depth: i32 = 5) -> proptest::Driver {
    proptest::driver_from_bytes(bytes, max_depth)
}

// Compatibility constructors
fn ::make_driver(iteration_seed: u64, max_depth: i32) -> proptest::Driver {
    proptest::driver(iteration_seed, max_depth)
}
fn ::make_recording_driver(iteration_seed: u64, max_depth: i32) -> proptest::Driver {
    proptest::recording_driver(iteration_seed, max_depth)
}
fn ::make_driver_from_bytes(bytes: const u8[:], max_depth: i32) -> proptest::Driver {
    proptest::driver_from_bytes(bytes, max_depth)
}

fn ::has_bytes(d: Driver&) -> bool {
    if !d.has_buf { return true; }
    d.cursor < d.buf.len
}

// assume signals that a generated input does not satisfy a precondition.
// The current iteration is discarded (not counted as a failure or a pass)
// and the run loop retries with a fresh input, up to the discard cap.
// Mirrors Hypothesis assume() and QuickCheck (==>).
//
// Usage:
//   check().for_each() { d =>
//       let x = d.gen_i64();
//       d.assume(x != 0);
//       100 / x != 0
//   };
//
// Can also be used as a guard expression:
//   if !d.assume(x != 0) { return true; }
fn ::assume(d: Driver&, cond: bool) -> bool {
    if !cond {
        d.assumed_false = true;
    }
    cond
}
fn assume(d: Driver&, cond: bool) -> bool {
    ::assume(d, cond)
}

// Synonym for assume.
fn ::filter(d: Driver&, cond: bool) -> bool {
    ::assume(d, cond)
}
fn filter(d: Driver&, cond: bool) -> bool {
    ::filter(d, cond)
}

fn ::is_discarded(d: Driver&) -> bool {
    d.assumed_false
}
fn is_discarded(d: Driver&) -> bool {
    ::is_discarded(d)
}

fn ::next_u8(d: Driver&) -> u8 {
    if d.has_buf {
        if d.cursor < d.buf.len {
            let b = d.buf[d.cursor];
            d.cursor += 1;
            if d.record_mode {
                d.recorded.push(b);
            }
            return b;
        }
        d.exhausted = true;
        return 0;
    }
    let b = (rand_u64(d.prng) & 0xFF) as u8;
    if d.record_mode {
        d.recorded.push(b);
    }
    return b;
}

fn ::next_u16(d: Driver&) -> u16 {
    if d.has_buf && !d.record_mode && d.cursor + 2 <= d.buf.len {
        let lo = d.buf[d.cursor] as u16;
        let hi = d.buf[d.cursor + 1] as u16;
        d.cursor += 2;
        return lo | (hi << 8);
    }
    let lo = next_u8(d) as u16;
    let hi = next_u8(d) as u16;
    lo | (hi << 8)
}

fn ::next_u32(d: Driver&) -> u32 {
    if d.has_buf && !d.record_mode && d.cursor + 4 <= d.buf.len {
        let b0 = d.buf[d.cursor] as u32;
        let b1 = d.buf[d.cursor + 1] as u32;
        let b2 = d.buf[d.cursor + 2] as u32;
        let b3 = d.buf[d.cursor + 3] as u32;
        d.cursor += 4;
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }
    let lo = next_u16(d) as u32;
    let hi = next_u16(d) as u32;
    lo | (hi << 16)
}

fn ::next_u64(d: Driver&) -> u64 {
    if !d.has_buf {
        if !d.record_mode {
            return rand_u64(d.prng);
        }
        let val = rand_u64(d.prng);
        d.recorded.push((val & 0xFF) as u8);
        d.recorded.push(((val >> 8) & 0xFF) as u8);
        d.recorded.push(((val >> 16) & 0xFF) as u8);
        d.recorded.push(((val >> 24) & 0xFF) as u8);
        d.recorded.push(((val >> 32) & 0xFF) as u8);
        d.recorded.push(((val >> 40) & 0xFF) as u8);
        d.recorded.push(((val >> 48) & 0xFF) as u8);
        d.recorded.push(((val >> 56) & 0xFF) as u8);
        return val;
    }
    if !d.record_mode && d.cursor + 8 <= d.buf.len {
        let b0 = d.buf[d.cursor] as u64;
        let b1 = d.buf[d.cursor + 1] as u64;
        let b2 = d.buf[d.cursor + 2] as u64;
        let b3 = d.buf[d.cursor + 3] as u64;
        let b4 = d.buf[d.cursor + 4] as u64;
        let b5 = d.buf[d.cursor + 5] as u64;
        let b6 = d.buf[d.cursor + 6] as u64;
        let b7 = d.buf[d.cursor + 7] as u64;
        d.cursor += 8;
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) |
               (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
    }
    if d.cursor >= d.buf.len {
        d.exhausted = true;
        return 0;
    }
    let b0 = next_u8(d) as u64;
    let b1 = next_u8(d) as u64;
    let b2 = next_u8(d) as u64;
    let b3 = next_u8(d) as u64;
    let b4 = next_u8(d) as u64;
    let b5 = next_u8(d) as u64;
    let b6 = next_u8(d) as u64;
    let b7 = next_u8(d) as u64;
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) |
           (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
}

fn ::next_bool(d: Driver&) -> bool {
    (next_u8(d) & 1) == 1
}

fn ::next_i8(d: Driver&) -> i8 {
    next_u8(d) as! i8
}

fn ::next_i16(d: Driver&) -> i16 {
    next_u16(d) as! i16
}

fn ::next_i32(d: Driver&) -> i32 {
    next_u32(d) as! i32
}

fn ::next_i64(d: Driver&) -> i64 {
    next_u64(d) as! i64
}

fn next_bool(d: Driver&) -> bool { ::next_bool(d) }
fn next_u8(d: Driver&) -> u8     { ::next_u8(d) }
fn next_u16(d: Driver&) -> u16   { ::next_u16(d) }
fn next_u32(d: Driver&) -> u32   { ::next_u32(d) }
fn next_u64(d: Driver&) -> u64   { ::next_u64(d) }
fn next_i8(d: Driver&) -> i8     { ::next_i8(d) }
fn next_i16(d: Driver&) -> i16   { ::next_i16(d) }
fn next_i32(d: Driver&) -> i32   { ::next_i32(d) }
fn next_i64(d: Driver&) -> i64   { ::next_i64(d) }

fn ::enter_depth(d: Driver&) -> bool {
    if d.depth >= d.max_depth { return false; }
    d.depth += 1;
    true
}

fn ::leave_depth(d: Driver&) {
    if d.depth > 0 { d.depth -= 1; }
}

struct Recording {
    bytes: u8[>..],
}
type ::Recording = proptest::Recording;

fn ::new_recording() -> Recording { Recording { bytes: [] } }

fn ::iteration_seed(base_seed: u64, iteration: i64) -> u64 {
    hash_mix(base_seed ^ (iteration as u64 + 1))
}

// ---- Generators ------------------------------------------------------------

fn ::gen_u64_range(d: Driver&, min: u64, max: u64) -> u64 {
    var lo = min;
    var hi = max;
    if lo > hi {
        let t = lo;
        lo = hi;
        hi = t;
    }
    let span = hi - lo;
    if span == 0 { return lo; }
    if (next_u8(d) % 10) == 0 {
        var candidates: u64[6] = [0; 6];
        var count = 0;
        candidates[count] = lo; count += 1;
        candidates[count] = hi; count += 1;
        if lo <= 0 && 0 <= hi { candidates[count] = 0; count += 1; }
        if lo <= 1 && 1 <= hi { candidates[count] = 1; count += 1; }
        if lo < hi { candidates[count] = lo + 1; count += 1; }
        if lo < hi { candidates[count] = hi - 1; count += 1; }
        let idx = next_u8(d) % count;
        return candidates[idx];
    }
    if span == 0xFFFFFFFFFFFFFFFF {
        return lo + next_u64(d);
    }
    let offset = next_u64(d) % (span + 1);
    return lo + offset;
}

fn ::gen_u64(d: Driver&) -> u64 {
    gen_u64_range(d, 0, 0xFFFFFFFFFFFFFFFF)
}
fn ::gen_u64(d: Driver&, min: u64, max: u64) -> u64 {
    gen_u64_range(d, min, max)
}

fn ::gen_i64_range(d: Driver&, min: i64, max: i64) -> i64 {
    var lo = min;
    var hi = max;
    if lo > hi {
        let t = lo;
        lo = hi;
        hi = t;
    }
    if lo == hi { return lo; }
    if (next_u8(d) % 10) == 0 {
        var candidates: i64[7] = [0; 7];
        var count = 0;
        candidates[count] = lo; count += 1;
        candidates[count] = hi; count += 1;
        if lo <= 0 && 0 <= hi { candidates[count] = 0; count += 1; }
        if lo <= 1 && 1 <= hi { candidates[count] = 1; count += 1; }
        if lo <= -1 && -1 <= hi { candidates[count] = -1; count += 1; }
        if lo < hi { candidates[count] = lo + 1; count += 1; }
        if lo < hi { candidates[count] = hi - 1; count += 1; }
        let idx = next_u8(d) % count;
        return candidates[idx];
    }
    let span = (hi as! u64) - (lo as! u64);
    if span == 0xFFFFFFFFFFFFFFFF {
        return (lo as! u64 + next_u64(d)) as! i64;
    }
    let offset = next_u64(d) % (span + 1);
    return (lo as! u64 + offset) as! i64;
}

fn ::gen_i64(d: Driver&) -> i64 {
    gen_i64_range(d, -9223372036854775807 - 1, 9223372036854775807)
}
fn ::gen_i64(d: Driver&, min: i64, max: i64) -> i64 {
    gen_i64_range(d, min, max)
}

fn ::gen_u32_range(d: Driver&, min: u32, max: u32) -> u32 {
    gen_u64_range(d, min, max) as u32
}
fn ::gen_u32(d: Driver&) -> u32 { next_u32(d) }
fn ::gen_u32(d: Driver&, min: u32, max: u32) -> u32 { gen_u32_range(d, min, max) }

fn ::gen_i32_range(d: Driver&, min: i32, max: i32) -> i32 {
    gen_i64_range(d, min, max) as! i32
}
fn ::gen_i32(d: Driver&) -> i32 { next_u32(d) as! i32 }
fn ::gen_i32(d: Driver&, min: i32, max: i32) -> i32 { gen_i32_range(d, min, max) }

fn ::gen_u16_range(d: Driver&, min: u16, max: u16) -> u16 {
    gen_u64_range(d, min, max) as u16
}
fn ::gen_u16(d: Driver&) -> u16 { next_u16(d) }
fn ::gen_u16(d: Driver&, min: u16, max: u16) -> u16 { gen_u16_range(d, min, max) }

fn ::gen_i16_range(d: Driver&, min: i16, max: i16) -> i16 {
    gen_i64_range(d, min, max) as! i16
}
fn ::gen_i16(d: Driver&) -> i16 { next_u16(d) as! i16 }
fn ::gen_i16(d: Driver&, min: i16, max: i16) -> i16 { gen_i16_range(d, min, max) }

fn ::gen_u8_range(d: Driver&, min: u8, max: u8) -> u8 {
    gen_u64_range(d, min, max) as u8
}
fn ::gen_u8(d: Driver&) -> u8 { next_u8(d) }
fn ::gen_u8(d: Driver&, min: u8, max: u8) -> u8 { gen_u8_range(d, min, max) }

fn ::gen_i8_range(d: Driver&, min: i8, max: i8) -> i8 {
    gen_i64_range(d, min, max) as! i8
}
fn ::gen_i8(d: Driver&) -> i8 { next_u8(d) as! i8 }
fn ::gen_i8(d: Driver&, min: i8, max: i8) -> i8 { gen_i8_range(d, min, max) }

fn ::gen_f64_range(d: Driver&, min: f64, max: f64) -> f64 {
    var lo = min;
    var hi = max;
    if lo > hi {
        let t = lo;
        lo = hi;
        hi = t;
    }
    if lo == hi { return lo; }
    if (next_u8(d) % 10) == 0 {
        var candidates: f64[6] = [0.0; 6];
        var count = 0;
        candidates[count] = lo; count += 1;
        candidates[count] = hi; count += 1;
        if lo <= 0.0 && 0.0 <= hi { candidates[count] = 0.0; count += 1; }
        if lo <= 0.0 && 0.0 <= hi { candidates[count] = -0.0; count += 1; }
        if lo <= 1.0 && 1.0 <= hi { candidates[count] = 1.0; count += 1; }
        if lo <= -1.0 && -1.0 <= hi { candidates[count] = -1.0; count += 1; }
        let idx = next_u8(d) % count;
        return candidates[idx];
    }
    let t = (next_u64(d) >> 11) as f64 / 9007199254740992.0;
    lo + (hi - lo) * t
}

fn ::gen_f64(d: Driver&) -> f64 {
    if (next_u8(d) % 10) == 0 {
        var candidates: f64[7] = [0.0; 7];
        let z = 0.0;
        candidates[0] = 0.0;
        candidates[1] = -0.0;
        candidates[2] = 1.0;
        candidates[3] = -1.0;
        candidates[4] = 1.0 / z;     // inf
        candidates[5] = -1.0 / z;    // -inf
        candidates[6] = z / z;       // nan
        let idx = next_u8(d) % 7;
        return candidates[idx];
    }
    let t = (next_u64(d) >> 11) as f64 / 9007199254740992.0;
    (t * 2000000.0) - 1000000.0
}
fn ::gen_f64(d: Driver&, min: f64, max: f64) -> f64 {
    gen_f64_range(d, min, max)
}

fn ::gen_f32_range(d: Driver&, min: f32, max: f32) -> f32 {
    var lo = min;
    var hi = max;
    if lo > hi {
        let t = lo;
        lo = hi;
        hi = t;
    }
    if lo == hi { return lo; }
    if (next_u8(d) % 10) == 0 {
        var candidates: f32[6] = [0.0; 6];
        var count = 0;
        candidates[count] = lo; count += 1;
        candidates[count] = hi; count += 1;
        if lo <= 0.0 && 0.0 <= hi { candidates[count] = 0.0; count += 1; }
        if lo <= 0.0 && 0.0 <= hi { candidates[count] = -0.0; count += 1; }
        if lo <= 1.0 && 1.0 <= hi { candidates[count] = 1.0; count += 1; }
        if lo <= -1.0 && -1.0 <= hi { candidates[count] = -1.0; count += 1; }
        let idx = next_u8(d) % count;
        return candidates[idx];
    }
    let t = (next_u32(d) >> 8) as f32 / 16777216.0;
    lo + (hi - lo) * t
}

fn ::gen_f32(d: Driver&) -> f32 {
    if (next_u8(d) % 10) == 0 {
        var candidates: f32[7] = [0.0; 7];
        let z: f32 = 0.0;
        candidates[0] = 0.0;
        candidates[1] = -0.0;
        candidates[2] = 1.0;
        candidates[3] = -1.0;
        candidates[4] = 1.0 / z;     // inf
        candidates[5] = -1.0 / z;    // -inf
        candidates[6] = z / z;       // nan
        let idx = next_u8(d) % 7;
        return candidates[idx];
    }
    let t = (next_u32(d) >> 8) as f32 / 16777216.0;
    (t * 200000.0) - 100000.0
}
fn ::gen_f32(d: Driver&, min: f32, max: f32) -> f32 {
    gen_f32_range(d, min, max)
}

fn ::next_f32(d: Driver&) -> f32 {
    gen_f32(d)
}

fn ::next_f64(d: Driver&) -> f64 {
    gen_f64(d)
}

fn next_f32(d: Driver&) -> f32 { ::next_f32(d) }
fn next_f64(d: Driver&) -> f64 { ::next_f64(d) }

fn ::gen_bool(d: Driver&) -> bool {
    (next_u8(d) & 1) == 1
}

fn gen_bool(d: Driver&) -> bool { ::gen_bool(d) }

fn ::gen_bool_prob(d: Driver&, p: f64) -> bool {
    if p <= 0.0 { return false; }
    if p >= 1.0 { return true; }
    let threshold = (p * 4294967296.0) as u64;
    next_u32(d) < threshold
}

fn ::gen_bytes(d: Driver&, min_len: i64, max_len: i64) -> u8[>..] {
    let len = gen_i64_range(d, min_len, max_len);
    var res: u8[>..] = [];
    if d.has_buf && !d.record_mode {
        let avail = d.buf.len - d.cursor;
        let take = if len < avail { len } else { avail };
        if take > 0 {
            res.append(d.buf[d.cursor..d.cursor + take]);
            d.cursor += take;
        }
        for _ in (len - take) {
            res.push(0);
        }
        if len > avail { d.exhausted = true; }
        return res;
    }
    for _ in len {
        res.push(next_u8(d));
    }
    res
}

fn ::gen_u8_array(d: Driver&, min_len: i64, max_len: i64) -> u8[>..] {
    gen_bytes(d, min_len, max_len)
}

fn gen_bytes(d: Driver&, min_len: i64, max_len: i64) -> u8[>..] {
    ::gen_bytes(d, min_len, max_len)
}

fn gen_u8_array(d: Driver&, min_len: i64, max_len: i64) -> u8[>..] {
    ::gen_u8_array(d, min_len, max_len)
}

fn ::gen_ascii_string(d: Driver&, min_len: i64, max_len: i64) -> u8[>..] {
    let len = gen_i64_range(d, min_len, max_len);
    var res: u8[>..] = [];
    for _ in len {
        let b = gen_u8_range(d, 32, 126);
        res.push(b);
    }
    res
}

fn ::_encode_utf8_cp(out: u8[>..]&, cp: u32) {
    if cp <= 0x7F {
        out.push(cp as u8);
    } else if cp <= 0x7FF {
        out.push((0xC0 | ((cp >> 6) & 0x1F)) as u8);
        out.push((0x80 | (cp & 0x3F)) as u8);
    } else if cp <= 0xFFFF {
        out.push((0xE0 | ((cp >> 12) & 0x0F)) as u8);
        out.push((0x80 | ((cp >> 6) & 0x3F)) as u8);
        out.push((0x80 | (cp & 0x3F)) as u8);
    } else if cp <= 0x10FFFF {
        out.push((0xF0 | ((cp >> 18) & 0x07)) as u8);
        out.push((0x80 | ((cp >> 12) & 0x3F)) as u8);
        out.push((0x80 | ((cp >> 6) & 0x3F)) as u8);
        out.push((0x80 | (cp & 0x3F)) as u8);
    }
}

fn ::gen_utf8_string(d: Driver&, min_len: i64, max_len: i64) -> u8[>..] {
    let target_len = gen_i64_range(d, min_len, max_len);
    var res: u8[>..] = [];
    while res.len < target_len {
        let mode = next_u8(d) % 10;
        var cp: u32 = 0;
        if mode < 6 {
            cp = gen_u32_range(d, 32, 126);
        } else if mode < 8 {
            cp = gen_u32_range(d, 0x00A0, 0x07FF);
        } else if mode < 9 {
            cp = gen_u32_range(d, 0x0800, 0xD7FF);
        } else {
            cp = gen_u32_range(d, 0xE000, 0x10FFFF);
        }
        if cp >= 0xD800 && cp <= 0xDFFF {
            cp = 0xFFFD;
        }
        var cp_bytes: u8[>..] = [];
        _encode_utf8_cp(cp_bytes, cp);
        if max_len >= 0 && res.len + cp_bytes.len > max_len {
            if res.len >= min_len { break; }
            res.push(gen_u8_range(d, 32, 126));
        } else {
            for b in cp_bytes { res.push(b); }
        }
    }
    res
}

fn ::gen_array<F>(d: Driver&, min_len: i64, max_len: i64) {
    let len = gen_i64_range(d, min_len, max_len);
    var out = [];
    for _ in len {
        out.push(F(&d));
    }
    return out;
}

fn ::gen_variant(d: Driver&, num_variants: i64) -> i64 {
    if num_variants <= 1 { return 0; }
    if !enter_depth(d) { return 0; }
    let v = gen_i64_range(d, 0, num_variants - 1);
    if v == 0 {
        leave_depth(d);
    }
    v
}

fn ::gen_one_of<T>(d: Driver&, choices: T[:]) -> T {
    if choices.len == 0 { abort("proptest: gen_one_of called with empty choices array"); }
    let idx = gen_i64_range(d, 0, choices.len - 1);
    choices[idx]
}

fn ::choose<T>(d: Driver&, choices: T[:]) -> T {
    gen_one_of(d, choices)
}

fn ::gen_choose<T>(d: Driver&, choices: T[:]) -> T {
    gen_one_of(d, choices)
}

fn choose<T>(d: Driver&, choices: T[:]) -> T {
    ::choose(d, choices)
}

fn gen_choose<T>(d: Driver&, choices: T[:]) -> T {
    ::gen_choose(d, choices)
}

fn one_of<T>(d: Driver&, choices: T[:]) -> T {
    ::one_of(d, choices)
}

fn ::int_range(d: Driver&, min: i64, max: i64) -> i64 {
    gen_i64_range(d, min, max)
}

fn ::gen_int_range(d: Driver&, min: i64, max: i64) -> i64 {
    gen_i64_range(d, min, max)
}

fn int_range(d: Driver&, min: i64, max: i64) -> i64 {
    ::int_range(d, min, max)
}

fn gen_int_range(d: Driver&, min: i64, max: i64) -> i64 {
    ::gen_int_range(d, min, max)
}

fn ::gen_frequency(d: Driver&, weights: const i64[:]) -> i64 {
    if weights.len == 0 {
        abort("proptest: frequency called with empty weights array");
    }
    var total: i64 = 0;
    for w in weights {
        if w > 0 { total += w; }
    }
    if total <= 0 {
        abort("proptest: frequency called with non-positive total weight");
    }
    let pick = gen_i64_range(d, 0, total - 1);
    var acc: i64 = 0;
    for i in weights.len {
        let w = weights[i];
        if w > 0 {
            acc += w;
            if pick < acc { return i; }
        }
    }
    return weights.len - 1;
}

fn ::frequency(d: Driver&, weights: const i64[:]) -> i64 {
    gen_frequency(d, weights)
}

fn frequency(d: Driver&, weights: const i64[:]) -> i64 {
    ::frequency(d, weights)
}

fn gen_frequency(d: Driver&, weights: const i64[:]) -> i64 {
    ::gen_frequency(d, weights)
}

// Clean alias methods for idiomatic UFCS:
fn ::bytes(d: Driver&, min_len: i64, max_len: i64) -> u8[>..]  { gen_bytes(d, min_len, max_len) }
fn ::ascii(d: Driver&, min_len: i64, max_len: i64) -> u8[>..]  { gen_ascii_string(d, min_len, max_len) }
fn ::utf8(d: Driver&, min_len: i64, max_len: i64) -> u8[>..]   { gen_utf8_string(d, min_len, max_len) }
fn ::array<F>(d: Driver&, min_len: i64, max_len: i64)          { gen_array(d, min_len, max_len, F) }
fn ::variant(d: Driver&, num_variants: i64) -> i64             { gen_variant(d, num_variants) }
fn ::one_of<T>(d: Driver&, choices: T[:]) -> T                 { gen_one_of(d, choices) }

fn bytes(d: Driver&, min_len: i64, max_len: i64) -> u8[>..]    { ::bytes(d, min_len, max_len) }
fn ascii(d: Driver&, min_len: i64, max_len: i64) -> u8[>..]    { ::ascii(d, min_len, max_len) }
fn utf8(d: Driver&, min_len: i64, max_len: i64) -> u8[>..]     { ::utf8(d, min_len, max_len) }
fn variant(d: Driver&, num_variants: i64) -> i64               { ::variant(d, num_variants) }

// ---- Universal Byte Shrinker -----------------------------------------------

struct ShrinkResult {
    steps:        i64,
    shrunk:       bool,
    shrunk_bytes: u8[>..],
}
type ::ShrinkResult = proptest::ShrinkResult;

fn ::shrink_bytes<F>(initial_bytes: const u8[:], max_depth: i32, max_steps: i64, max_time_ms: i64) -> ShrinkResult {
    var current: u8[>..] = [];
    for b in initial_bytes { current.push(b); }

    var steps: i64 = 0;
    let start_ns = clock_ns();
    let max_time_ns = max_time_ms * 1000000;

    var outer_iter = 0;
    while outer_iter < 5 && steps < max_steps && (clock_ns() - start_ns) < max_time_ns {
        outer_iter += 1;
        var prev_round: u8[>..] = [];
        for b in current { prev_round.push(b); }

        // --- Pass 1: Suffix Truncation (Binary Search) ---
        var low: i64 = 0;
        var high: i64 = current.len;
        steps += 1;
        var d0 = make_driver_from_bytes(current[0..0], max_depth);
        let ok0 = F(&d0);
        if !ok0 && !d0.assumed_false {
            high = 0;
        } else {
            low = 1;
            while low < high && steps < max_steps && (clock_ns() - start_ns) < max_time_ns {
                let mid = low + (high - low) / 2;
                steps += 1;
                var dmid = make_driver_from_bytes(current[0..mid], max_depth);
                let ok_mid = F(&dmid);
                if !ok_mid && !dmid.assumed_false {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
        }
        if high < current.len {
            var trunc: u8[>..] = [];
            for j in high { trunc.push(current[j]); }
            current = copy(trunc);
        }

        // --- Pass 2: Chunk Deletion (Power-of-Two Slicing) ---
        var k = current.len / 2;
        while k >= 1 && steps < max_steps && (clock_ns() - start_ns) < max_time_ns {
            var offset: i64 = 0;
            let step_size = if k > 16 { k } else { 1 };
            while offset + k <= current.len && steps < max_steps && (clock_ns() - start_ns) < max_time_ns {
                var cand: u8[>..] = [];
                for j in offset { cand.push(current[j]); }
                for j in (offset + k)..current.len { cand.push(current[j]); }
                steps += 1;
                var dcand = make_driver_from_bytes(cand[..], max_depth);
                let ok_cand = F(&dcand);
                if !ok_cand && !dcand.assumed_false {
                    current = copy(cand);
                } else {
                    offset += step_size;
                }
            }
            k = k / 2;
        }

        // --- Pass 3: Per-Byte Minimization toward Zero (Binary Search) ---
        // Word alignment helper: try lowering high byte and setting low byte to 255
        if current.len >= 2 {
            for i in current.len - 1 {
                if steps >= max_steps || (clock_ns() - start_ns) >= max_time_ns { break; }
                if current[i + 1] > 0 {
                    let old_hi = current[i + 1];
                    let old_lo = current[i];
                    current[i + 1] = 0;
                    current[i] = 255;
                    steps += 1;
                    var d_sh = make_driver_from_bytes(current[..], max_depth);
                    let ok_sh = F(&d_sh);
                    if ok_sh || d_sh.assumed_false {
                        current[i + 1] = old_hi;
                        current[i] = old_lo;
                    }
                }
            }
        }

        // Backward pass: higher-order bytes of integers minimized first
        for idx in current.len {
            if steps >= max_steps || (clock_ns() - start_ns) >= max_time_ns { break; }
            let i = current.len - 1 - idx;
            if current[i] > 0 {
                let old_val = current[i];
                current[i] = 0;
                steps += 1;
                var d_b0 = make_driver_from_bytes(current[..], max_depth);
                let ok_b0 = F(&d_b0);
                if !ok_b0 && !d_b0.assumed_false {
                    // keep 0
                } else {
                    var b_low: i32 = 0;
                    var b_high: i32 = old_val as i32;
                    while b_low + 1 < b_high && steps < max_steps && (clock_ns() - start_ns) < max_time_ns {
                        let mid = b_low + (b_high - b_low) / 2;
                        current[i] = mid as u8;
                        steps += 1;
                        var d_bmid = make_driver_from_bytes(current[..], max_depth);
                        let ok_bmid = F(&d_bmid);
                        if !ok_bmid && !d_bmid.assumed_false {
                            b_high = mid;
                        } else {
                            b_low = mid;
                        }
                    }
                    current[i] = b_high as u8;
                }
            }
        }

        // Forward pass: lower-order bytes and strings minimized
        for i in current.len {
            if steps >= max_steps || (clock_ns() - start_ns) >= max_time_ns { break; }
            if current[i] > 0 {
                let old_val = current[i];
                current[i] = 0;
                steps += 1;
                var d_f0 = make_driver_from_bytes(current[..], max_depth);
                let ok_f0 = F(&d_f0);
                if !ok_f0 && !d_f0.assumed_false {
                    // keep 0
                } else {
                    var b_low: i32 = 0;
                    var b_high: i32 = old_val as i32;
                    while b_low + 1 < b_high && steps < max_steps && (clock_ns() - start_ns) < max_time_ns {
                        let mid = b_low + (b_high - b_low) / 2;
                        current[i] = mid as u8;
                        steps += 1;
                        var d_fmid = make_driver_from_bytes(current[..], max_depth);
                        let ok_fmid = F(&d_fmid);
                        if !ok_fmid && !d_fmid.assumed_false {
                            b_high = mid;
                        } else {
                            b_low = mid;
                        }
                    }
                    current[i] = b_high as u8;
                }
            }
        }

        // --- Pass 4: Bit Minimization ---
        for i in current.len {
            if steps >= max_steps || (clock_ns() - start_ns) < max_time_ns { break; }
            for b_idx in 8 {
                if steps >= max_steps || (clock_ns() - start_ns) < max_time_ns { break; }
                let bit = 7 - b_idx;
                if (current[i] & ((1 << bit) as u8)) != 0 {
                    let old_val = current[i];
                    current[i] = current[i] & ~((1 << bit) as u8);
                    steps += 1;
                    var d_bit = make_driver_from_bytes(current[..], max_depth);
                    let ok_bit = F(&d_bit);
                    if ok_bit || d_bit.assumed_false {
                        current[i] = old_val;
                    }
                }
            }
        }

        // Fixpoint check
        var changed = false;
        if current.len != prev_round.len {
            changed = true;
        } else {
            for idx in current.len {
                if current[idx] != prev_round[idx] {
                    changed = true;
                    break;
                }
            }
        }
        if !changed {
            break;
        }
    }

    var did_shrink = false;
    if current.len < initial_bytes.len {
        did_shrink = true;
    } else {
        for idx in current.len {
            if current[idx] != initial_bytes[idx] {
                did_shrink = true;
                break;
            }
        }
    }

    ShrinkResult {
        steps:        steps,
        shrunk:       did_shrink,
        shrunk_bytes: current,
    }
}

fn ::_print_hex(bytes: const u8[:]) {
    var out: u8[>..] = [];
    var i = 0;
    while i < bytes.len {
        if (i % 16) == 0 {
            if i > 0 {
                out.append("  |");
                var ascii_start = i - 16;
                while ascii_start < i {
                    let c = bytes[ascii_start];
                    if c >= 32 && c <= 126 { out.push(c); } else { out.push('.'); }
                    ascii_start += 1;
                }
                out.append("|\n");
            }
            let hex_chars = "0123456789abcdef";
            out.push(hex_chars[(i >> 12) & 0xF]);
            out.push(hex_chars[(i >> 8) & 0xF]);
            out.push(hex_chars[(i >> 4) & 0xF]);
            out.push(hex_chars[i & 0xF]);
            out.append(": ");
        }
        let b = bytes[i];
        let hex_chars = "0123456789abcdef";
        out.push(hex_chars[(b >> 4) & 0xF]);
        out.push(hex_chars[b & 0xF]);
        out.push(' ');
        if (i % 8) == 7 { out.push(' '); }
        i += 1;
    }
    // Pad last line
    let remainder = i % 16;
    if remainder > 0 {
        var pad_count = 16 - remainder;
        for _ in pad_count {
            out.append("   ");
        }
        if remainder <= 8 { out.push(' '); }
        out.append("  |");
        var ascii_start = i - remainder;
        while ascii_start < i {
            let c = bytes[ascii_start];
            if c >= 32 && c <= 126 { out.push(c); } else { out.push('.'); }
            ascii_start += 1;
        }
        out.append("|");
    } else if i > 0 {
        out.append("  |");
        var ascii_start = i - 16;
        while ascii_start < i {
            let c = bytes[ascii_start];
            if c >= 32 && c <= 126 { out.push(c); } else { out.push('.'); }
            ascii_start += 1;
        }
        out.append("|");
    }
    print(out);
}

// Result of a property test or fuzzing run.
struct TestResult {
    passed:             bool,
    failed_iteration:   i64,
    failed_seed:        u64,
    base_seed:          u64,
    total_iterations:   i64,
    discarded_iterations: i64,
    elapsed_ns:         i64,
    shrunk:             bool,
    shrink_steps:       i64,
    original_bytes_len: i64,
    shrunk_bytes_len:   i64,
    saved_crash_file:   const u8[:],
    shrunk_bytes:       u8[>..],
}
type ::TestResult = proptest::TestResult;

fn ::_save_crash_if_configured(c: Config, final_bytes: const u8[:]) -> const u8[:] {
    if should_save_crashes(c) && final_bytes.len > 0 {
        let path = crash_file_path(c);
        if write_file(path, final_bytes) {
            return path;
        }
    }
    ""
}

fn ::elapsed_s(r: TestResult&) -> f64 {
    r.elapsed_ns / 1000000000.0
}

fn ::iters_per_sec(r: TestResult&) -> f64 {
    let s = elapsed_s(r);
    if s > 0.0 {
        let count = if r.passed { r.total_iterations } else { r.failed_iteration + 1 };
        count / s
    } else {
        0.0
    }
}

// ---- Mutators --------------------------------------------------------------

fn ::mut_bit_flip(buf: u8[>..]&, r: rng&) {
    if buf.len == 0 { return; }
    let idx = rand_int(r, buf.len);
    let bit = rand_int(r, 8);
    let mask: u8 = (1 << bit) as u8;
    buf[idx] = buf[idx] ^ mask;
}

fn ::mut_byte_flip(buf: u8[>..]&, r: rng&) {
    if buf.len == 0 { return; }
    let idx = rand_int(r, buf.len);
    buf[idx] = buf[idx] ^ 0xFF;
}

fn ::mut_byte_replace(buf: u8[>..]&, r: rng&) {
    if buf.len == 0 { return; }
    let idx = rand_int(r, buf.len);
    let interesting: u8[10] = [0, 1, 2, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF, 42];
    if (rand_u64(r) & 1) == 0 {
        let val_idx = rand_int(r, 10);
        buf[idx] = interesting[val_idx];
    } else {
        buf[idx] = (rand_u64(r) & 0xFF) as u8;
    }
}

fn ::mut_byte_delete(buf: u8[>..]&, r: rng&, min_len: i64) {
    if buf.len <= min_len { return; }
    let max_del = if (buf.len - min_len) < 4 { buf.len - min_len } else { 4 };
    let del_count = 1 + rand_int(r, max_del);
    let start_idx = rand_int(r, buf.len - del_count + 1);

    var res: u8[>..] = [];
    for i in start_idx { res.push(buf[i]); }
    for i in (start_idx + del_count)..buf.len { res.push(buf[i]); }
    buf = copy(res);
}

fn ::mut_byte_insert(buf: u8[>..]&, r: rng&, max_len: i64) {
    if buf.len >= max_len { return; }
    let max_ins = if (max_len - buf.len) < 4 { max_len - buf.len } else { 4 };
    let ins_count = 1 + rand_int(r, max_ins);
    let insert_idx = if buf.len > 0 { rand_int(r, buf.len + 1) } else { 0 };

    var res: u8[>..] = [];
    for i in insert_idx { res.push(buf[i]); }
    for _ in ins_count {
        res.push((rand_u64(r) & 0xFF) as u8);
    }
    for i in insert_idx..buf.len { res.push(buf[i]); }
    buf = copy(res);
}

fn ::mut_chunk_copy(buf: u8[>..]&, r: rng&, max_len: i64) {
    if buf.len < 2 { return; }
    let src_start = rand_int(r, buf.len);
    let max_src_len = buf.len - src_start;
    let chunk_len = 1 + rand_int(r, if max_src_len < 16 { max_src_len } else { 16 });

    let mode = rand_int(r, 2);
    if mode == 0 {
        // Overwrite chunk at random dest
        let dst_start = rand_int(r, buf.len - chunk_len + 1);
        for i in chunk_len {
            buf[dst_start + i] = buf[src_start + i];
        }
    } else {
        // Insert chunk if within max_len
        if buf.len + chunk_len <= max_len {
            let dst_start = rand_int(r, buf.len + 1);
            var res: u8[>..] = [];
            for i in dst_start { res.push(buf[i]); }
            for i in chunk_len { res.push(buf[src_start + i]); }
            for i in dst_start..buf.len { res.push(buf[i]); }
            buf = copy(res);
        }
    }
}

fn ::mut_interesting_int(buf: u8[>..]&, r: rng&) {
    if buf.len < 2 { return; }
    let widths: i64[3] = [2, 4, 8];
    let w_idx = rand_int(r, 3);
    let width = widths[w_idx];
    if buf.len < width { return; }

    let pos = rand_int(r, buf.len - width + 1);
    let ints_16: u16[5] = [0, 1, 0x7FFF, 0x8000, 0xFFFF];
    let ints_32: u32[5] = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF];

    if width == 2 {
        let v = ints_16[rand_int(r, 5)];
        buf[pos] = (v & 0xFF) as u8;
        buf[pos + 1] = ((v >> 8) & 0xFF) as u8;
    } else if width == 4 {
        let v = ints_32[rand_int(r, 5)];
        buf[pos] = (v & 0xFF) as u8;
        buf[pos + 1] = ((v >> 8) & 0xFF) as u8;
        buf[pos + 2] = ((v >> 16) & 0xFF) as u8;
        buf[pos + 3] = ((v >> 24) & 0xFF) as u8;
    }
}

fn ::mutate(buf: u8[>..]&, r: rng&, min_len: i64, max_len: i64) {
    if buf.len == 0 {
        buf.push((rand_u64(r) & 0xFF) as u8);
        return;
    }
    let n_mutations = 1 + rand_int(r, 3);
    for _ in n_mutations {
        let op = rand_int(r, 7);
        if op == 0 { mut_bit_flip(buf, r); }
        else if op == 1 { mut_byte_flip(buf, r); }
        else if op == 2 { mut_byte_replace(buf, r); }
        else if op == 3 { mut_byte_delete(buf, r, min_len); }
        else if op == 4 { mut_byte_insert(buf, r, max_len); }
        else if op == 5 { mut_chunk_copy(buf, r, max_len); }
        else { mut_interesting_int(buf, r); }
    }
}

fn ::_corpus_add(corpus_data: u8[>..]&, corpus_lens: i64[>..]&, corpus_offsets: i64[>..]&, entry: const u8[:]) {
    corpus_offsets.push(corpus_data.len);
    corpus_lens.push(entry.len);
    for b in entry {
        corpus_data.push(b);
    }
}

fn ::_corpus_get(corpus_data: const u8[:], corpus_lens: const i64[:], corpus_offsets: const i64[:], idx: i64) -> u8[>..] {
    let off = corpus_offsets[idx];
    let len = corpus_lens[idx];
    var res: u8[>..] = [];
    for i in len {
        res.push(corpus_data[off + i]);
    }
    res
}

// ---- Runners ---------------------------------------------------------------

fn ::_replay_run<F>(c: Config) -> TestResult {
    let max_depth = max_depth_or_default(c);
    var replay_buf: u8[>..] = [];

    if c.opt_replay_bytes.len > 0 {
        for b in c.opt_replay_bytes { replay_buf.push(b); }
    } else if c.opt_replay_file.len > 0 {
        if !read_file(c.opt_replay_file, replay_buf) {
            print("proptest [error]: cannot read replay artifact: ", c.opt_replay_file);
            return TestResult {
                passed:             false,
                failed_iteration:   0,
                failed_seed:        0,
                base_seed:          0,
                total_iterations:   0,
                discarded_iterations: 0,
                elapsed_ns:         0,
                shrunk:             false,
                shrink_steps:       0,
                original_bytes_len: 0,
                shrunk_bytes_len:   0,
                saved_crash_file:   "",
                shrunk_bytes:       [],
            };
        }
    }

    let start_ns = clock_ns();
    var d = make_driver_from_bytes(replay_buf[..], max_depth);
    let passed = F(&d);
    let discarded = d.assumed_false;
    let elapsed_ns = clock_ns() - start_ns;

    if !passed && !discarded {
        var did_shrink = false;
        var s_steps: i64 = 0;
        let orig_bytes_len = replay_buf.len;
        var s_bytes_len = orig_bytes_len;
        var final_bytes: u8[>..] = copy(replay_buf);

        if c.opt_shrink && orig_bytes_len > 0 {
            let max_steps = shrink_steps_or_default(c);
            let max_time_ms = shrink_time_ms_or_default(c);
            let sr = shrink_bytes(replay_buf[..], max_depth, max_steps, max_time_ms, F);
            s_steps = sr.steps;
            did_shrink = sr.shrunk;
            final_bytes = copy(sr.shrunk_bytes);
            s_bytes_len = final_bytes.len;

            var minimal_d = make_driver_from_bytes(final_bytes[..], max_depth);
            let _ = F(&minimal_d);
        }

        let saved_path = _save_crash_if_configured(c, final_bytes[..]);

        TestResult {
            passed:             false,
            failed_iteration:   0,
            failed_seed:        0,
            base_seed:          0,
            total_iterations:   1,
            discarded_iterations: 0,
            elapsed_ns:         elapsed_ns,
            shrunk:             did_shrink,
            shrink_steps:       s_steps,
            original_bytes_len: orig_bytes_len,
            shrunk_bytes_len:   s_bytes_len,
            saved_crash_file:   saved_path,
            shrunk_bytes:       final_bytes,
        }
    } else {
        if c.opt_verbose {
            let elapsed_sec = elapsed_ns / 1000000000.0;
            if discarded {
                print("proptest [replay]: input filtered by assume() (vacuously passed)");
            } else {
                print("proptest [replay]: 1 passed in ", elapsed_sec, "s");
            }
        }
        TestResult {
            passed:             true,
            failed_iteration:   -1,
            failed_seed:        0,
            base_seed:          0,
            total_iterations:   if discarded { 0 } else { 1 },
            discarded_iterations: if discarded { 1 } else { 0 },
            elapsed_ns:         elapsed_ns,
            shrunk:             false,
            shrink_steps:       0,
            original_bytes_len: 0,
            shrunk_bytes_len:   0,
            saved_crash_file:   "",
            shrunk_bytes:       [],
        }
    }
}

fn ::_push_str(out: u8[>..]&, s: const u8[:]) {
    for b in s { out.push(b); }
}

fn ::_push_num(out: u8[>..]&, n: i64) {
    if n == 0 { out.push(48); return; }
    var v = if n < 0 { out.push(45); -n } else { n };
    var digits: u8[32] = [0; 32];
    var count = 0;
    while v > 0 {
        digits[count] = (48 + (v % 10)) as u8;
        count += 1;
        v = v / 10;
    }
    for idx in count {
        out.push(digits[count - 1 - idx]);
    }
}

fn ::_push_num_padded(out: u8[>..]&, n: i64, width: i32) {
    var digits: u8[32] = [0; 32];
    var count = 0;
    var v = n;
    if v == 0 {
        digits[0] = 48;
        count = 1;
    } else {
        while v > 0 {
            digits[count] = (48 + (v % 10)) as u8;
            count += 1;
            v = v / 10;
        }
    }
    let n_pad = width - count;
    for _ in n_pad { out.push(48); }
    for idx in count {
        out.push(digits[count - 1 - idx]);
    }
}

fn ::_fuzz_stderr_is_live() -> bool {
    // Respect GOOSE_PROGRESS=plain|live; fall back to isatty.
    var val: u8[>..] = [];
    if env("GOOSE_PROGRESS", val) {
        if val[..] == "plain" { return false; }
        if val[..] == "live"  { return true;  }
    }
    stderr_is_tty()
}

fn ::_print_fuzz_progress(iter: i64, elapsed_ns: i64, corpus_count: i64, max_len: i64) {
    let elapsed_sec = elapsed_ns / 1000000000;
    let s = elapsed_sec % 60;
    let m = (elapsed_sec / 60) % 60;
    let h = elapsed_sec / 3600;
    let rate = if elapsed_sec > 0 { iter / elapsed_sec } else { 0 };
    let live = _fuzz_stderr_is_live();

    var line: u8[>..] = [];
    if live { line.push(13); } else { line.push(10); } // '\r' live, '\n' plain
    line.push(32); line.push(32); // "  "
    line.push(91); // '['
    _push_num_padded(line, h, 2);
    line.push(58); // ':'
    _push_num_padded(line, m, 2);
    line.push(58); // ':'
    _push_num_padded(line, s, 2);
    line.push(93); // ']'
    _push_str(line, " execs: ");
    _push_num(line, iter);
    _push_str(line, " (");
    _push_num(line, rate);
    _push_str(line, "/s) | corpus: ");
    _push_num(line, corpus_count);
    _push_str(line, " | max_len: ");
    _push_num(line, max_len);
    _push_str(line, "   ");
    write_stderr(line[..]);
}

fn ::_clear_fuzz_progress() {
    // Only erase the live line when stderr is actually a terminal.
    if !_fuzz_stderr_is_live() { return; }
    var line: u8[>..] = [];
    line.push(13);
    for _ in 80 { line.push(32); }
    line.push(13);
    write_stderr(line[..]);
}

fn ::_fuzz_run<F>(c: Config) -> TestResult {
    let n_iterations = iterations_or_default(c);
    let base_seed = seed_or_default(c);
    let max_depth = max_depth_or_default(c);
    let max_buf_len = max_len_or_default(c);
    let t_limit_ms = timeout_ms_or_default(c);
    let max_corpus = corpus_size_or_default(c);

    var r = rng { s: base_seed };

    var corpus_data: u8[>..] = [];
    var corpus_lens: i64[>..] = [];
    var corpus_offsets: i64[>..] = [];

    // Seed corpus
    var s1: u8[>..] = [0];
    _corpus_add(corpus_data, corpus_lens, corpus_offsets, s1[..]);

    var s2: u8[>..] = [];
    let l2 = if max_buf_len < 4 { max_buf_len } else { 4 };
    for _ in l2 { s2.push(0); }
    if s2.len > 0 { _corpus_add(corpus_data, corpus_lens, corpus_offsets, s2[..]); }

    var s3: u8[>..] = [];
    let l3 = if max_buf_len < 16 { max_buf_len } else { 16 };
    for _ in l3 { s3.push((rand_u64(r) & 0xFF) as u8); }
    if s3.len > 0 { _corpus_add(corpus_data, corpus_lens, corpus_offsets, s3[..]); }

    var s4: u8[>..] = [];
    let l4 = if max_buf_len < 64 { max_buf_len } else { 64 };
    for _ in l4 { s4.push((rand_u64(r) & 0xFF) as u8); }
    if s4.len > 0 { _corpus_add(corpus_data, corpus_lens, corpus_offsets, s4[..]); }

    let start_ns = clock_ns();
    var last_progress_ns = start_ns;
    let max_time_ns = t_limit_ms * 1000000;
    var completed: i64 = 0;
    var discarded_count: i64 = 0;
    var failed = false;
    var fail_iter: i64 = -1;
    var crashing_input: u8[>..] = [];

    var i: i64 = 0;
    while n_iterations <= 0 || i < n_iterations {
        if t_limit_ms > 0 && (clock_ns() - start_ns) >= max_time_ns {
            break;
        }

        if (i % 500) == 0 && c.opt_verbose {
            let cur_ns = clock_ns();
            if (cur_ns - last_progress_ns) >= 200000000 {
                last_progress_ns = cur_ns;
                _print_fuzz_progress(i, cur_ns - start_ns, corpus_lens.len, max_buf_len);
            }
        }

        var cand: u8[>..] = [];
        if i < corpus_lens.len {
            cand = _corpus_get(corpus_data[..], corpus_lens[..], corpus_offsets[..], i);
        } else {
            let entry_idx = rand_int(r, corpus_lens.len);
            cand = _corpus_get(corpus_data[..], corpus_lens[..], corpus_offsets[..], entry_idx);
            mutate(cand, r, 1, max_buf_len);
        }

        var d = make_driver_from_bytes(cand[..], max_depth);
        let ok = F(&d);

        if d.assumed_false {
            discarded_count += 1;
            i += 1;
            continue;
        }

        if !ok {
            failed = true;
            fail_iter = i;
            crashing_input = copy(cand);
            completed = i + 1;
            break;
        }

        if corpus_lens.len < max_corpus {
            var has_len = false;
            for l in corpus_lens {
                if l == cand.len {
                    has_len = true;
                    break;
                }
            }
            if !has_len || rand_int(r, 20) == 0 {
                _corpus_add(corpus_data, corpus_lens, corpus_offsets, cand[..]);
            }
        }

        i += 1;
        completed = i;
    }

    if c.opt_verbose {
        _clear_fuzz_progress();
    }

    let elapsed_ns = clock_ns() - start_ns;

    if c.opt_verbose {
        let elapsed_sec = elapsed_ns / 1000000000.0;
        let rate = if elapsed_sec > 0.0 { completed / elapsed_sec } else { 0.0 };
        if failed {
            print("proptest [fuzz]: FAILED at iteration ", fail_iter, " in ", elapsed_sec, "s (", rate as! i64, " iters/sec)");
        } else {
            print("proptest [fuzz]: ", completed, " passed (", discarded_count, " discarded) in ", elapsed_sec, "s (", rate as! i64, " iters/sec)");
        }
    }

    if failed {
        var did_shrink = false;
        var s_steps: i64 = 0;
        let orig_bytes_len = crashing_input.len;
        var s_bytes_len = orig_bytes_len;
        var final_bytes: u8[>..] = copy(crashing_input);

        if c.opt_shrink && orig_bytes_len > 0 {
            let max_steps = shrink_steps_or_default(c);
            let max_time_ms = shrink_time_ms_or_default(c);
            let sr = shrink_bytes(crashing_input[..], max_depth, max_steps, max_time_ms, F);
            s_steps = sr.steps;
            did_shrink = sr.shrunk;
            final_bytes = copy(sr.shrunk_bytes);
            s_bytes_len = final_bytes.len;

            var minimal_d = make_driver_from_bytes(final_bytes[..], max_depth);
            let _ = F(&minimal_d);
        }

        let saved_path = _save_crash_if_configured(c, final_bytes[..]);

        TestResult {
            passed:             false,
            failed_iteration:   fail_iter,
            failed_seed:        base_seed,
            base_seed:          base_seed,
            total_iterations:   completed,
            discarded_iterations: discarded_count,
            elapsed_ns:         elapsed_ns,
            shrunk:             did_shrink,
            shrink_steps:       s_steps,
            original_bytes_len: orig_bytes_len,
            shrunk_bytes_len:   s_bytes_len,
            saved_crash_file:   saved_path,
            shrunk_bytes:       final_bytes,
        }
    } else {
        TestResult {
            passed:             true,
            failed_iteration:   -1,
            failed_seed:        0,
            base_seed:          base_seed,
            total_iterations:   completed,
            discarded_iterations: discarded_count,
            elapsed_ns:         elapsed_ns,
            shrunk:             false,
            shrink_steps:       0,
            original_bytes_len: 0,
            shrunk_bytes_len:   0,
            saved_crash_file:   "",
            shrunk_bytes:       [],
        }
    }
}

// Execute a property test campaign.
fn ::run<F>(c: Config) -> TestResult {
    if c.opt_has_replay {
        return _replay_run(c, F);
    }
    if c.opt_fuzz {
        return _fuzz_run(c, F);
    }

    let n_iterations = iterations_or_default(c);
    let base_seed = seed_or_default(c);
    let max_depth = max_depth_or_default(c);
    let max_discards = max_discards_or_default(c);

    let start_ns = clock_ns();
    var failed = false;
    var fail_iter: i64 = -1;
    var fail_seed: u64 = 0;
    var completed: i64 = 0;
    var discarded_count: i64 = 0;
    var attempt: i64 = 0;

    while completed < n_iterations {
        let iter_seed = if n_iterations == 1 && attempt == 0 {
            base_seed
        } else {
            iteration_seed(base_seed, attempt)
        };
        attempt += 1;

        var d = make_driver(iter_seed, max_depth);
        let ok = F(&d);

        if d.assumed_false {
            discarded_count += 1;
            if discarded_count >= max_discards {
                if c.opt_verbose {
                    print("proptest [warning]: gave up after ", discarded_count, " discarded inputs (unable to meet assumptions via d.assume)");
                }
                failed = true;
                fail_iter = completed;
                fail_seed = iter_seed;
                break;
            }
            continue;
        }

        if !ok {
            failed = true;
            fail_iter = completed;
            fail_seed = iter_seed;
            completed += 1;
            break;
        }

        completed += 1;
    }

    let elapsed_ns = clock_ns() - start_ns;

    if c.opt_verbose {
        let elapsed_sec = elapsed_ns / 1000000000.0;
        let rate = if elapsed_sec > 0.0 { completed / elapsed_sec } else { 0.0 };
        if failed {
            print("proptest: FAILED at iteration ", fail_iter, " in ", elapsed_sec, "s (", rate as! i64, " iters/sec)");
        } else {
            print("proptest: ", completed, " passed (", discarded_count, " discarded) in ", elapsed_sec, "s (", rate as! i64, " iters/sec)");
        }
    }

    if failed {
        var did_shrink = false;
        var s_steps: i64 = 0;
        var orig_bytes_len: i64 = 0;
        var s_bytes_len: i64 = 0;
        var final_bytes: u8[>..] = [];

        if c.opt_shrink && fail_iter >= 0 {
            var recording_d = make_recording_driver(fail_seed, max_depth);
            let _ = F(&recording_d);
            if !recording_d.assumed_false {
                let recorded_bytes = copy(recording_d.recorded);
                orig_bytes_len = recorded_bytes.len;

                if orig_bytes_len > 0 {
                    let max_steps = shrink_steps_or_default(c);
                    let max_time_ms = shrink_time_ms_or_default(c);
                    let sr = shrink_bytes(recorded_bytes[..], max_depth, max_steps, max_time_ms, F);
                    s_steps = sr.steps;
                    did_shrink = sr.shrunk;
                    final_bytes = copy(sr.shrunk_bytes);
                    s_bytes_len = final_bytes.len;

                    var minimal_d = make_driver_from_bytes(final_bytes[..], max_depth);
                    let _ = F(&minimal_d);
                }
            }
        }

        let saved_path = _save_crash_if_configured(c, final_bytes[..]);

        TestResult {
            passed:             false,
            failed_iteration:   fail_iter,
            failed_seed:        fail_seed,
            base_seed:          base_seed,
            total_iterations:   completed,
            discarded_iterations: discarded_count,
            elapsed_ns:         elapsed_ns,
            shrunk:             did_shrink,
            shrink_steps:       s_steps,
            original_bytes_len: orig_bytes_len,
            shrunk_bytes_len:   s_bytes_len,
            saved_crash_file:   saved_path,
            shrunk_bytes:       final_bytes,
        }
    } else {
        TestResult {
            passed:             true,
            failed_iteration:   -1,
            failed_seed:        0,
            base_seed:          base_seed,
            total_iterations:   completed,
            discarded_iterations: discarded_count,
            elapsed_ns:         elapsed_ns,
            shrunk:             false,
            shrink_steps:       0,
            original_bytes_len: 0,
            shrunk_bytes_len:   0,
            saved_crash_file:   "",
            shrunk_bytes:       [],
        }
    }
}

// Namespaced mirror
fn run<F>(c: Config) -> TestResult {
    ::run(c, F)
}

// Standard test runner. Runs property and aborts on failure after printing
// a reproduction diagnostic banner.
fn ::for_each<F>(c: Config) {
    let res = run(c, F);
    if !res.passed {
        print("======================== Test Failure ========================");
        if c.opt_has_replay {
            if c.opt_replay_file.len > 0 {
                print("Replay failed from artifact: ", c.opt_replay_file);
            } else {
                print("Replay failed from in-memory bytes");
            }
        } else {
            print("Property failed at iteration: ", res.failed_iteration, " / ", res.total_iterations);
            print("Iteration seed: ", res.failed_seed, " (base seed: ", res.base_seed, ")");
        }
        if res.discarded_iterations > 0 {
            print("Discarded iterations: ", res.discarded_iterations);
        }
        if res.shrunk || res.original_bytes_len > 0 {
            print("Shrinking: ", res.original_bytes_len, " bytes -> ", res.shrunk_bytes_len, " bytes (", res.shrink_steps, " steps)");
        }
        if res.shrunk_bytes_len > 0 {
            print("Minimal failing bytes (hex):");
            _print_hex(res.shrunk_bytes[..]);
        }
        if res.saved_crash_file.len > 0 {
            print("Saved minimal crash artifact to: ", res.saved_crash_file);
        }
        print("Reproduction:");
        let is_cli_fuzz = c.opt_fuzz_source_file.len > 0 && c.opt_fuzz_target_name.len > 0;
        if is_cli_fuzz {
            // CLI fuzz target: users never see check().for_each(); give them the goose fuzz command.
            if res.saved_crash_file.len > 0 {
                print("  goose fuzz ", c.opt_fuzz_source_file,
                      " --target ", c.opt_fuzz_target_name,
                      " --replay ", res.saved_crash_file);
                if res.shrunk_bytes_len > 0 {
                    print("  (or paste the hex above into --replay)");
                }
            } else if res.shrunk_bytes_len > 0 {
                print("  goose fuzz ", c.opt_fuzz_source_file,
                      " --target ", c.opt_fuzz_target_name,
                      " --replay \"<hex-from-above>\"");
            } else if res.failed_seed != 0 {
                print("  goose fuzz ", c.opt_fuzz_source_file,
                      " --target ", c.opt_fuzz_target_name,
                      " --seed ", res.failed_seed);
            }
        } else {
            if res.saved_crash_file.len > 0 {
                print("  proptest::check().replay(\"", res.saved_crash_file, "\").for_each() { d => ... }");
            }
            if res.failed_seed != 0 {
                print("  proptest::check().seed(", res.failed_seed, ").iterations(1).for_each() { d => ... }");
            }
        }
        print("==============================================================");
        abort("proptest: property check failed");
    }
}

// Namespaced mirror
fn for_each<F>(c: Config) {
    ::for_each(c, F)
}

// ---- Contained Execution ---------------------------------------------------

struct ContainedInput {
    data: u8[],
}
type ::ContainedInput = proptest::ContainedInput;

fn ::eval_contained<W>(bytes: const u8[:], why: u8[>..]&) -> bool {
    let id = thread_spawn_contained(W, ContainedInput { data: bytes });
    let ok = thread_wait(id, why);
    ok
}

fn ::shrink_contained<W>(initial_bytes: const u8[:], max_depth: i32, max_steps: i64, max_time_ms: i64) -> ShrinkResult {
    shrink_bytes(initial_bytes, max_depth, max_steps, max_time_ms) { d =>
        var why: u8[>..] = [];
        let id = thread_spawn_contained(W, ContainedInput { data: d.buf });
        let ok = thread_wait(id, why);
        ok
    }
}

fn ::run_contained<W>(c: Config) -> TestResult {
    run(c) { d =>
        var cand: u8[>..] = [];
        if d.has_buf {
            cand.append(d.buf);
            d.cursor = d.buf.len;
        } else {
            let len = gen_i64_range(d, 1, max_len_or_default(c));
            cand = gen_bytes(d, len, len);
        }
        var why: u8[>..] = [];
        let id = thread_spawn_contained(W, ContainedInput { data: cand[..] });
        let ok = thread_wait(id, why);
        ok
    }
}
fn run_contained<W>(c: Config) -> TestResult {
    ::run_contained(c, W)
}

fn ::for_each_contained<W>(c: Config) {
    let res = run_contained(c, W);
    if !res.passed {
        print("======================== Test Failure ========================");
        if c.opt_has_replay {
            if c.opt_replay_file.len > 0 {
                print("Replay failed from artifact: ", c.opt_replay_file);
            } else {
                print("Replay failed from in-memory bytes");
            }
        } else {
            print("Property failed at iteration: ", res.failed_iteration, " / ", res.total_iterations);
            print("Iteration seed: ", res.failed_seed, " (base seed: ", res.base_seed, ")");
        }
        if res.discarded_iterations > 0 {
            print("Discarded iterations: ", res.discarded_iterations);
        }
        if res.shrunk || res.original_bytes_len > 0 {
            print("Shrinking: ", res.original_bytes_len, " bytes -> ", res.shrunk_bytes_len, " bytes (", res.shrink_steps, " steps)");
        }
        if res.shrunk_bytes_len > 0 {
            print("Minimal failing bytes (hex):");
            _print_hex(res.shrunk_bytes[..]);
        }
        if res.saved_crash_file.len > 0 {
            print("Saved minimal crash artifact to: ", res.saved_crash_file);
        }
        print("Reproduction:");
        let is_cli_fuzz = c.opt_fuzz_source_file.len > 0 && c.opt_fuzz_target_name.len > 0;
        if is_cli_fuzz {
            // CLI fuzz target: users never see run_contained; give them the goose fuzz command.
            if res.saved_crash_file.len > 0 {
                print("  goose fuzz ", c.opt_fuzz_source_file,
                      " --target ", c.opt_fuzz_target_name,
                      " --replay ", res.saved_crash_file);
                if res.shrunk_bytes_len > 0 {
                    print("  (or paste the hex above into --replay)");
                }
            } else if res.shrunk_bytes_len > 0 {
                print("  goose fuzz ", c.opt_fuzz_source_file,
                      " --target ", c.opt_fuzz_target_name,
                      " --replay \"<hex-from-above>\"");
            } else if res.failed_seed != 0 {
                print("  goose fuzz ", c.opt_fuzz_source_file,
                      " --target ", c.opt_fuzz_target_name,
                      " --seed ", res.failed_seed);
            }
        } else {
            // In-code proptest: run_contained is user-visible.
            if res.saved_crash_file.len > 0 {
                print("  proptest::check().replay(\"", res.saved_crash_file, "\").run_contained(...)");
            }
            if res.failed_seed != 0 {
                print("  proptest::check().seed(", res.failed_seed, ").iterations(1).for_each() { d => ... }");
            }
        }
        print("==============================================================");
        abort("proptest: contained property check failed");
    }
}
fn for_each_contained<W>(c: Config) {
    ::for_each_contained(c, W)
}
