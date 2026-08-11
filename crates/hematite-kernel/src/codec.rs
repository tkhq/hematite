//! Pure byte codecs used by the swap engine (Part 04 §3.2). Hand-rolled to
//! keep the dependency budget closed (Appendix E): base64 for
//! `Authorization: Basic`, percent-encoding for query/path substitution,
//! and a byte-level replace-all.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18 & 0x3f) as usize] as char);
        out.push(B64[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6 & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64. Returns `None` on any invalid input (so a
/// non-base64 `Basic` value is left untouched rather than corrupted).
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.trim().as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a' + 26)),
            b'0'..=b'9' => Some(u32::from(c - b'0' + 52)),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' { 0 } else { val(c)? };
            // Padding is only legal in the last one or two positions.
            if c == b'=' && i < 2 {
                return None;
            }
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16 & 0xff) as u8);
        if pad < 2 {
            out.push((n >> 8 & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
    }
    Some(out)
}

/// Percent-encode per RFC 3986: everything except the unreserved set
/// (ALPHA / DIGIT / `-` `.` `_` `~`) is `%XX`-escaped.
pub fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(
                char::from_digit(u32::from(b >> 4), 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
            out.push(
                char::from_digit(u32::from(b & 0xf), 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
        }
    }
    out
}

/// Replace every occurrence of `needle` in `haystack` with `replacement`.
/// Returns the rewritten bytes and the number of replacements made.
pub fn replace_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> (Vec<u8>, usize) {
    if needle.is_empty() {
        return (haystack.to_vec(), 0);
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut count = 0;
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(replacement);
            i += needle.len();
            count += 1;
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    (out, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_and_known_vectors() {
        assert_eq!(base64_encode(b"proxy-tok:x"), "cHJveHktdG9rOng=");
        assert_eq!(base64_decode("cHJveHktdG9rOng=").unwrap(), b"proxy-tok:x");
        assert_eq!(base64_encode(b"sk-real:x"), "c2stcmVhbDp4");
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            assert_eq!(
                base64_decode(&base64_encode(s.as_bytes())).unwrap(),
                s.as_bytes()
            );
        }
        assert!(base64_decode("not base64!!").is_none());
        assert!(base64_decode("abc").is_none()); // not a multiple of 4
    }

    #[test]
    fn percent_encode_unreserved_and_reserved() {
        assert_eq!(percent_encode(b"sk-real"), "sk-real");
        assert_eq!(percent_encode(b"a/b c"), "a%2Fb%20c");
        assert_eq!(percent_encode(b"tok+en="), "tok%2Ben%3D");
    }

    #[test]
    fn replace_all_counts_and_rewrites() {
        assert_eq!(replace_all(b"aXbXc", b"X", b"Y"), (b"aYbYc".to_vec(), 2));
        assert_eq!(replace_all(b"none", b"X", b"Y"), (b"none".to_vec(), 0));
        assert_eq!(replace_all(b"abc", b"", b"Y"), (b"abc".to_vec(), 0));
    }
}
