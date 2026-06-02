//! A minimal standard-base64 (RFC 4648 §4) decoder for the inbox wire fields.
//!
//! The gateway carries `metadata_cbor_base64` as standard base64; the CLI
//! decodes it before validating the record. A self-contained decoder keeps the dependency
//! graph small and the behaviour explicit; it accepts the canonical alphabet
//! with `=` padding and rejects anything else.

const INVALID: u8 = 0xFF;

/// Build the reverse lookup table for the standard base64 alphabet.
const fn decode_table() -> [u8; 256] {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [INVALID; 256];
    let mut i = 0;
    while i < alphabet.len() {
        table[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    table
}

const DECODE: [u8; 256] = decode_table();

/// Decode a standard-base64 string (with `=` padding) to bytes.
///
/// # Errors
///
/// Returns an error string for an invalid length, a non-alphabet character, or
/// misplaced padding.
pub fn decode_standard(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return Err("base64: input length is not a multiple of 4".to_string());
    }

    // Count trailing padding.
    let pad = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return Err("base64: too much padding".to_string());
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut vals = [0u8; 4];
        let mut chunk_pad = 0;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                // Padding only permitted in the final positions of the final chunk.
                chunk_pad += 1;
                vals[i] = 0;
                continue;
            }
            if chunk_pad != 0 {
                return Err("base64: data character after padding".to_string());
            }
            let v = DECODE[b as usize];
            if v == INVALID {
                return Err("base64: invalid character".to_string());
            }
            vals[i] = v;
        }
        let triple = (u32::from(vals[0]) << 18)
            | (u32::from(vals[1]) << 12)
            | (u32::from(vals[2]) << 6)
            | u32::from(vals[3]);
        out.push((triple >> 16) as u8);
        if chunk_pad < 2 {
            out.push((triple >> 8) as u8);
        }
        if chunk_pad < 1 {
            out.push(triple as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_vectors() {
        assert_eq!(decode_standard("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(decode_standard("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(decode_standard("Zm8=").unwrap(), b"fo");
        assert_eq!(decode_standard("").unwrap(), b"");
    }

    #[test]
    fn rejects_bad_length() {
        assert!(decode_standard("SGVsbG").is_err());
    }

    #[test]
    fn rejects_invalid_char() {
        assert!(decode_standard("SGV*bG8=").is_err());
    }
}
