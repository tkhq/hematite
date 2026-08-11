//! Shared test helper: validate an emitted audit record against the
//! normative JSON Schema (Part 08 §2, Appendix A step 10).

// Each test binary that includes this module uses a subset of the helpers.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::OnceLock;

use hematite_kernel::audit::AuditRecord;
use jsonschema::Validator;

fn validator() -> &'static Validator {
    static V: OnceLock<Validator> = OnceLock::new();
    V.get_or_init(|| {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/schema/audit-record.schema.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read schema {}: {e}", path.display()));
        let schema: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
        jsonschema::validator_for(&schema).expect("schema compiles")
    })
}

/// Assert a record serializes to a form that satisfies the normative schema
/// (`additionalProperties: false`, conditional requireds, etc.).
pub fn assert_valid_record(record: &AuditRecord) {
    let value = serde_json::to_value(record).expect("record serializes");
    if let Err(error) = validator().validate(&value) {
        panic!("audit record violates the schema: {error}\nrecord: {value:#}");
    }
}

/// Assert a JSON value does NOT satisfy the schema (for negative tests).
pub fn assert_invalid(value: &serde_json::Value) {
    assert!(
        validator().validate(value).is_err(),
        "value unexpectedly passed the schema: {value:#}"
    );
}
