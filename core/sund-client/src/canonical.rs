//! Canonical JSON: the one encoding every signature in this stack is computed
//! over.
//!
//! `docs/FamilyBeacon-Roster.md` states the reason in one line — "a signature
//! scheme with two encodings is a signature scheme with a forgery" — and the
//! roster's vouches, its tombstones and the key bundles of
//! `docs/FamilyBeacon-Sessions.md` all sign structures rather than opaque
//! bytes. Three implementations exist (this crate, Sund's Go side, beaconsim in
//! Python), so the encoding has to be pinned somewhere both machine-checkable
//! and boring.
//!
//! The rules, in full:
//!
//! - Object keys are sorted ascending by their UTF-8 bytes.
//! - No insignificant whitespace anywhere.
//! - No floating-point numbers. This is the one rule that rejects input rather
//!   than encoding it, because a float has no single shortest representation
//!   every language agrees on, and a signature over an ambiguous encoding is
//!   the forgery the rule above warns about. Nothing signed in this stack
//!   carries one: coordinates travel inside an *encrypted envelope*, which is
//!   sealed rather than signed.
//!
//! Sorting falls out of `serde_json`'s default `Map` being a `BTreeMap`, which
//! is load-bearing rather than incidental — the `preserve_order` feature would
//! silently replace it with an insertion-ordered map and break every signature
//! this crate has ever made. [`tests::keys_are_sorted_not_insertion_ordered`]
//! is the tripwire.

use serde::Serialize;

/// Why a value could not be encoded canonically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// The value could not be turned into JSON at all.
    NotSerializable(String),
    /// The value contained a floating-point number, which has no canonical
    /// form. The path names where, so the caller can fix the type rather than
    /// guess.
    FloatingPoint {
        /// Dotted path to the offending number, e.g. `subject.accuracy`.
        path: String,
    },
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSerializable(detail) => write!(f, "not serializable as JSON: {detail}"),
            Self::FloatingPoint { path } => {
                write!(f, "floating-point number at `{path}` has no canonical form")
            }
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Encode a value as canonical JSON.
///
/// # Errors
///
/// Returns [`CanonicalError`] if the value cannot be represented as JSON, or if
/// it contains a floating-point number.
pub fn to_canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    // Round-tripping through Value is what does the sorting: a struct
    // serializes in declaration order, a Value's map in key order.
    let value = serde_json::to_value(value)
        .map_err(|error| CanonicalError::NotSerializable(error.to_string()))?;
    reject_floats(&value, "")?;
    serde_json::to_vec(&value).map_err(|error| CanonicalError::NotSerializable(error.to_string()))
}

fn reject_floats(value: &serde_json::Value, path: &str) -> Result<(), CanonicalError> {
    match value {
        serde_json::Value::Number(number)
            if number.as_i64().is_none() && number.as_u64().is_none() =>
        {
            Err(CanonicalError::FloatingPoint {
                path: if path.is_empty() {
                    "<root>".to_owned()
                } else {
                    path.to_owned()
                },
            })
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                reject_floats(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        serde_json::Value::Object(fields) => {
            for (key, field) in fields {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                reject_floats(field, &child)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_sorted_not_insertion_ordered() {
        // The tripwire for `serde_json`'s `preserve_order` feature. If someone
        // enables it — directly or through a dependency's feature unification —
        // this fails here rather than as a signature nobody can explain.
        let json = r#"{"zebra":1,"alpha":2,"middle":{"z":1,"a":2}}"#;
        let value: serde_json::Value = serde_json::from_str(json).expect("parses");
        let canonical = to_canonical_json(&value).expect("encodes");
        assert_eq!(
            String::from_utf8(canonical).expect("utf-8"),
            r#"{"alpha":2,"middle":{"a":2,"z":1},"zebra":1}"#
        );
    }

    #[test]
    fn declaration_order_does_not_leak_from_a_struct() {
        #[derive(Serialize)]
        struct OutOfOrder {
            zulu: u8,
            alpha: u8,
        }

        let canonical = to_canonical_json(&OutOfOrder { zulu: 1, alpha: 2 }).expect("encodes");
        assert_eq!(
            String::from_utf8(canonical).expect("utf-8"),
            r#"{"alpha":2,"zulu":1}"#
        );
    }

    #[test]
    fn no_insignificant_whitespace() {
        let json = "{ \"a\" : [ 1 , 2 ] }";
        let value: serde_json::Value = serde_json::from_str(json).expect("parses");
        let canonical = to_canonical_json(&value).expect("encodes");
        assert_eq!(
            String::from_utf8(canonical).expect("utf-8"),
            r#"{"a":[1,2]}"#
        );
    }

    #[test]
    fn a_float_is_refused_and_named() {
        let json = r#"{"subject":{"accuracy":1.5}}"#;
        let value: serde_json::Value = serde_json::from_str(json).expect("parses");
        assert_eq!(
            to_canonical_json(&value),
            Err(CanonicalError::FloatingPoint {
                path: "subject.accuracy".to_owned()
            })
        );
    }

    #[test]
    fn a_float_inside_an_array_is_refused_with_its_index() {
        let json = r#"{"points":[1,2.5]}"#;
        let value: serde_json::Value = serde_json::from_str(json).expect("parses");
        assert_eq!(
            to_canonical_json(&value),
            Err(CanonicalError::FloatingPoint {
                path: "points[1]".to_owned()
            })
        );
    }

    #[test]
    fn integers_are_fine_including_negative_and_large() {
        let json = r#"{"a":-9007199254740993,"b":18446744073709551615}"#;
        let value: serde_json::Value = serde_json::from_str(json).expect("parses");
        assert!(to_canonical_json(&value).is_ok());
    }

    #[test]
    fn non_ascii_keys_sort_by_utf8_bytes() {
        // Swedish is a first-class UI language here, so the ordering of å/ä/ö
        // is not hypothetical. Byte order, not locale collation.
        let json = r#"{"ö":1,"a":2,"å":3}"#;
        let value: serde_json::Value = serde_json::from_str(json).expect("parses");
        let canonical = to_canonical_json(&value).expect("encodes");
        assert_eq!(
            String::from_utf8(canonical).expect("utf-8"),
            r#"{"a":2,"å":3,"ö":1}"#
        );
    }
}
