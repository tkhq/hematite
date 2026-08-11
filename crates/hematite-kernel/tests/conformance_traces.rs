//! Appendix C §4 (spec/vectors/decision-traces.json) — reject vector at
//! L0; full-pipeline vector at L3.

mod common;

use hematite_kernel::audit::conformance_record;
use hematite_kernel::config::{build_pipeline, build_pipeline_with_resolver, TransformSpec};

use common::MapResolver;

fn run_case(case: &serde_json::Value) -> serde_json::Value {
    let specs: Vec<TransformSpec> =
        serde_json::from_value(case["pipeline"].clone()).expect("vector pipeline deserializes");
    let built = match case.get("resolver") {
        Some(resolver) => {
            let resolver = MapResolver::from_value(resolver);
            build_pipeline_with_resolver(&specs, &resolver).expect("vector pipeline builds")
        }
        None => build_pipeline(&specs).expect("vector pipeline builds"),
    };
    let summary: common::VectorSummary =
        serde_json::from_value(case["summary"].clone()).expect("vector summary deserializes");
    let mut summary = summary.into_summary();
    let outcome = built.pipeline.evaluate_request(&mut summary);
    let mut record = serde_json::to_value(conformance_record(&summary, &outcome))
        .expect("record serializes");
    common::strip_duration_ms(&mut record);
    record
}

#[test]
fn reject_l0() {
    let vectors = common::load_vector("decision-traces.json");
    let case = &vectors["reject_l0"];
    let mut expected = case["expected_record"].clone();
    common::strip_duration_ms(&mut expected);
    let got = run_case(case);
    assert_eq!(
        got, expected,
        "reject_l0 record mismatch\n got: {got:#}\nwant: {expected:#}"
    );
}

#[test]
fn full_pipeline_l3() {
    let vectors = common::load_vector("decision-traces.json");
    let case = &vectors["full_pipeline_l3"];
    let mut expected = case["expected_record"].clone();
    common::strip_duration_ms(&mut expected);
    let got = run_case(case);
    assert_eq!(got, expected, "full_pipeline_l3 record mismatch");

    // The negative half: no serialized structure may contain the forbidden
    // byte string (INV-1).
    let forbidden = case["forbidden_bytes"].as_str().unwrap();
    assert!(
        !got.to_string().contains(forbidden),
        "serialized record contains the resolved secret"
    );
}
