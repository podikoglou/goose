// The Goose standard library: `vec` (docs/stdlib.md): small vectors as
// plain structs. Elementwise + - * / are the language's (§6.1); the
// scalar * / broadcast too. The functions here combine components. The int aliases are
// i32 because vectors are data (§3.1), and an i32 component widens into an
// i64 index implicitly.

import math;

struct vec2<T> { x: T, y: T }
struct vec3<T> { x: T, y: T, z: T }
struct vec4<T> { x: T, y: T, z: T, w: T }

type float2 = vec2<f32>;
type float3 = vec3<f32>;
type float4 = vec4<f32>;
type double2 = vec2<f64>;
type double3 = vec3<f64>;
type double4 = vec4<f64>;
type int2 = vec2<i32>;
type int3 = vec3<i32>;
type int4 = vec4<i32>;

let float2_0 = float2 { 0.0, 0.0 };
let float2_1 = float2 { 1.0, 1.0 };
let float3_0 = float3 { 0.0, 0.0, 0.0 };
let float3_1 = float3 { 1.0, 1.0, 1.0 };
let float4_0 = float4 { 0.0, 0.0, 0.0, 0.0 };
let float4_1 = float4 { 1.0, 1.0, 1.0, 1.0 };
let double2_0 = double2 { 0.0, 0.0 };
let double2_1 = double2 { 1.0, 1.0 };
let double3_0 = double3 { 0.0, 0.0, 0.0 };
let double3_1 = double3 { 1.0, 1.0, 1.0 };
let double4_0 = double4 { 0.0, 0.0, 0.0, 0.0 };
let double4_1 = double4 { 1.0, 1.0, 1.0, 1.0 };
let int2_0 = int2 { 0, 0 };
let int2_1 = int2 { 1, 1 };
let int3_0 = int3 { 0, 0, 0 };
let int3_1 = int3 { 1, 1, 1 };
let int4_0 = int4 { 0, 0, 0, 0 };
let int4_1 = int4 { 1, 1, 1, 1 };

prop "commutativity" for (ax: f64), (ay: f64), (bx: f64), (by: f64) where ax in -1000..=1000, ay in -1000..=1000, bx in -1000..=1000, by in -1000..=1000 {
    let a = double2 { ax, ay };
    let b = double2 { bx, by };
    dot(a, b) == dot(b, a)
}
prop "distributivity" for (ax: f64), (ay: f64), (bx: f64), (by: f64), (cx: f64), (cy: f64) where ax in -100..=100, ay in -100..=100, bx in -100..=100, by in -100..=100, cx in -100..=100, cy in -100..=100 {
    let a = double2 { ax, ay };
    let b = double2 { bx, by };
    let c = double2 { cx, cy };
    let diff = dot(a, b + c) - (dot(a, b) + dot(a, c));
    diff < 1e-6 && diff > -1e-6
}
fn dot<T>(a: vec2<T>, b: vec2<T>) -> T { a.x * b.x + a.y * b.y }
fn dot<T>(a: vec3<T>, b: vec3<T>) -> T { a.x * b.x + a.y * b.y + a.z * b.z }
fn dot<T>(a: vec4<T>, b: vec4<T>) -> T { a.x * b.x + a.y * b.y + a.z * b.z + a.w * b.w }

prop "anti-commutativity" for (ax: f64), (ay: f64), (az: f64), (bx: f64), (by: f64), (bz: f64) where ax in -100..=100, ay in -100..=100, az in -100..=100, bx in -100..=100, by in -100..=100, bz in -100..=100 {
    let a = double3 { ax, ay, az };
    let b = double3 { bx, by, bz };
    let c1 = cross(a, b);
    let c2 = cross(b, a);
    c1.x == -c2.x && c1.y == -c2.y && c1.z == -c2.z
}
prop "self cross is zero" for (ax: f64), (ay: f64), (az: f64) where ax in -1000..=1000, ay in -1000..=1000, az in -1000..=1000 {
    let a = double3 { ax, ay, az };
    let c = cross(a, a);
    c.x == 0.0 && c.y == 0.0 && c.z == 0.0
}
fn cross<T>(a: vec3<T>, b: vec3<T>) -> vec3<T> {
    vec3<T> { a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x }
}

fn length_sq<T>(v: vec2<T>) -> T { dot(v, v) }
fn length_sq<T>(v: vec3<T>) -> T { dot(v, v) }
fn length_sq<T>(v: vec4<T>) -> T { dot(v, v) }

// Float vectors only: sqrt has f32 and f64 forms.
fn length<T>(v: vec2<T>) -> T { sqrt(length_sq(v)) }
fn length<T>(v: vec3<T>) -> T { sqrt(length_sq(v)) }
fn length<T>(v: vec4<T>) -> T { sqrt(length_sq(v)) }

prop "normalization length is 1" for (x: f64), (y: f64) where x in 1..=1000, y in 1..=1000 {
    let v = double2 { x, y };
    let n = normalize(v);
    let diff = length(n) - 1.0;
    diff < 1e-6 && diff > -1e-6
}
fn normalize<T>(v: vec2<T>) -> vec2<T> { v / length(v) }
fn normalize<T>(v: vec3<T>) -> vec3<T> { v / length(v) }
fn normalize<T>(v: vec4<T>) -> vec4<T> { v / length(v) }

prop "symmetry" for (ax: f64), (ay: f64), (bx: f64), (by: f64) where ax in -1000..=1000, ay in -1000..=1000, bx in -1000..=1000, by in -1000..=1000 {
    let a = double2 { ax, ay };
    let b = double2 { bx, by };
    distance(a, b) == distance(b, a)
}
prop "identity" for (x: f64), (y: f64) where x in -1000..=1000, y in -1000..=1000 {
    let a = double2 { x, y };
    distance(a, a) == 0.0
}
fn distance<T>(a: vec2<T>, b: vec2<T>) -> T { length(a - b) }
fn distance<T>(a: vec3<T>, b: vec3<T>) -> T { length(a - b) }
fn distance<T>(a: vec4<T>, b: vec4<T>) -> T { length(a - b) }

fn lerp<T>(a: vec2<T>, b: vec2<T>, t: T) -> vec2<T> {
    vec2<T> { a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t }
}
fn lerp<T>(a: vec3<T>, b: vec3<T>, t: T) -> vec3<T> {
    vec3<T> { a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, a.z + (b.z - a.z) * t }
}
fn lerp<T>(a: vec4<T>, b: vec4<T>, t: T) -> vec4<T> {
    vec4<T> { a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, a.z + (b.z - a.z) * t,
              a.w + (b.w - a.w) * t }
}

fn xy<T>(v: vec3<T>) -> vec2<T> { vec2<T> { v.x, v.y } }
fn xy<T>(v: vec4<T>) -> vec2<T> { vec2<T> { v.x, v.y } }
fn xyz<T>(v: vec4<T>) -> vec3<T> { vec3<T> { v.x, v.y, v.z } }
