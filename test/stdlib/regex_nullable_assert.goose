import std;
import regex;

fn check(pattern: u8[:], expected: bool) {
    let re = regex::compile(pattern);
    let nullable = regex::is_nullable(re);
    let matches_empty = regex::matches(re, "");
    assert(nullable == expected);
    assert(matches_empty == expected);
    assert(nullable == matches_empty);
    print(pattern, " nullable=", nullable, " matches_empty=", matches_empty, " ok");
}

fn main() {
    // Assertions required by specification
    check("\\b", false);
    check("\\B", true);
    check("^", true);
    check("$", true);
    check("^$", true);
    check("^a", false);
    check("\\bword\\b", false);

    // Combinations of assertions, alternations, repetitions
    check("\\b|a", false);
    check("\\b|\\B", true);
    check("a|\\b", false);
    check("a|\\B", true);
    check("(?:\\b)?", true);
    check("(?:\\b)+", false);
    check("(?:\\b)*", true);
    check("(?:\\B)?", true);
    check("(?:\\B)+", true);
    check("(?:\\B)*", true);
    check("^.*$", true);
    check("^.+word$", false);
    check("\\b.*", false);
    check("\\B.*", true);
    check("^\\b$", false);
    check("^\\B$", true);
    check("\\b\\b", false);
    check("\\B\\B", true);

    // Non-assertion patterns for sanity
    check("", true);
    check("a", false);
    check("a*", true);
    check("a+", false);
    check("a?", true);

    print("all regex nullable assert tests passed");
}
