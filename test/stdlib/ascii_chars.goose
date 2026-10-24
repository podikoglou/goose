// runtime-debug: ASCII byte predicates and single-byte conversions.
import std;

fn test_predicates_full_range() {
    var alpha_count = 0;
    var digit_count = 0;
    var alnum_count = 0;
    var hex_count = 0;
    var alnum_matches_union = true;

    for i in 256 {
        let b = i as u8;
        if is_alpha(b) {
            alpha_count += 1;
            assert((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'));
        }
        if is_digit(b) {
            digit_count += 1;
            assert(b >= '0' && b <= '9');
        }
        if is_alnum(b) {
            alnum_count += 1;
            assert(is_alpha(b) || is_digit(b));
        }
        if is_hex_digit(b) {
            hex_count += 1;
            assert(is_digit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F'));
        }
        if is_alnum(b) != (is_alpha(b) || is_digit(b)) {
            alnum_matches_union = false;
        }
    }

    print("alpha_count: ", alpha_count);
    print("digit_count: ", digit_count);
    print("alnum_count: ", alnum_count);
    print("hex_count: ", hex_count);
    print("alnum_matches_union: ", alnum_matches_union);
}

fn test_conversions_full_range() {
    var lower_changed = 0;
    var upper_changed = 0;
    var idempotent_lower = true;
    var idempotent_upper = true;

    for i in 256 {
        let b = i as u8;
        let lo = to_lower_ascii(b);
        let up = to_upper_ascii(b);

        if lo != b {
            lower_changed += 1;
            assert(b >= 'A' && b <= 'Z');
            assert(lo == b + 32);
        }
        if up != b {
            upper_changed += 1;
            assert(b >= 'a' && b <= 'z');
            assert(up == b - 32);
        }

        if to_lower_ascii(lo) != lo { idempotent_lower = false; }
        if to_upper_ascii(up) != up { idempotent_upper = false; }
    }

    print("lower_changed: ", lower_changed);
    print("upper_changed: ", upper_changed);
    print("idempotent: ", idempotent_lower && idempotent_upper);
}

fn test_specific_characters() {
    // Digits
    print("digits: ", is_digit('0'), " ", is_digit('9'), " ", is_alpha('5'), " ", is_alnum('5'), " ", is_hex_digit('5'));

    // Boundary around '0' (48) and '9' (57)
    print("digit bounds: ", is_digit(47), " ", is_digit(48), " ", is_digit(57), " ", is_digit(58));

    // Lowercase alpha
    print("lower: ", is_alpha('a'), " ", is_alpha('z'), " ", is_alnum('k'));

    // Boundary around 'a' (97) and 'z' (122)
    print("lower bounds: ", is_alpha(96), " ", is_alpha(97), " ", is_alpha(122), " ", is_alpha(123));

    // Uppercase alpha
    print("upper: ", is_alpha('A'), " ", is_alpha('Z'), " ", is_alnum('K'));

    // Boundary around 'A' (65) and 'Z' (90)
    print("upper bounds: ", is_alpha(64), " ", is_alpha(65), " ", is_alpha(90), " ", is_alpha(91));

    // Hex digits
    print("hex: ", is_hex_digit('0'), " ", is_hex_digit('9'), " ", is_hex_digit('a'), " ", is_hex_digit('f'), " ", is_hex_digit('A'), " ", is_hex_digit('F'));
    print("hex non-match: ", is_hex_digit('g'), " ", is_hex_digit('G'), " ", is_hex_digit('x'), " ", is_hex_digit('X'));

    // Control characters (0, 9=\t, 10=\n, 13=\r, 27=\e, 31, 127=DEL)
    print("control: ", is_alnum(0), " ", is_alnum('\t'), " ", is_alnum('\n'), " ", is_alnum('\r'), " ", is_alnum(27), " ", is_alnum(127));
    print("control conv: ", to_lower_ascii('\n') == '\n', " ", to_upper_ascii(0) == 0);

    // Punctuation and symbols (' ', '!', '@', '[', '`', '{', '~')
    print("punct: ", is_alnum(' '), " ", is_alnum('!'), " ", is_alnum('@'), " ", is_alnum('['), " ", is_alnum('`'), " ", is_alnum('{'), " ", is_alnum('~'));
    print("punct conv: ", to_lower_ascii('!') == '!', " ", to_upper_ascii('~') == '~');

    // High bytes (non-ASCII: 128, 160, 192, 255)
    let b128: u8 = 128;
    let b160: u8 = 160;
    let b192: u8 = 192;
    let b255: u8 = 255;
    print("high bytes pred: ", is_alpha(b128), " ", is_digit(b160), " ", is_alnum(b192), " ", is_hex_digit(b255));
    print("high bytes conv: ", to_lower_ascii(b128) == b128, " ", to_upper_ascii(b255) == b255);
}

fn test_ufcs() {
    let c_digit: u8 = '7';
    let c_upper: u8 = 'G';
    let c_lower: u8 = 'g';
    let c_space: u8 = ' ';

    print("ufcs pred: ", c_digit.is_digit(), " ", c_upper.is_alpha(), " ", c_lower.is_hex_digit(), " ", c_space.is_alnum());
    print("ufcs conv: ", c_upper.to_lower_ascii() == 'g', " ", c_lower.to_upper_ascii() == 'G', " ", c_digit.to_lower_ascii() == '7');
}

fn main() {
    test_predicates_full_range();
    test_conversions_full_range();
    test_specific_characters();
    test_ufcs();
}
