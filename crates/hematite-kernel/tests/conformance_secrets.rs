//! Appendix C §2 (spec/vectors/secrets-swap.json) — L3.
//!
//! Each case is run through a real pipeline (allowlist + secrets) so the
//! secrets transform sees a genuine `RequestSummary`; the mutated request
//! and the secrets trace annotations are checked against the vector.

mod common;

use serde_json::{json, Value};

use hematite_kernel::config::{build_pipeline_with_resolver, TransformSpec};
use hematite_kernel::pipeline::Outcome;
use hematite_kernel::summary::{Body, Headers, Mode, RequestSummary};
use hematite_kernel::verdict::TraceVerdict;

use common::MapResolver;

fn summary_from(request: &Value) -> RequestSummary {
    let headers: Vec<(String, String)> = request["headers"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|p| {
                    (
                        p[0].as_str().unwrap().to_string(),
                        p[1].as_str().unwrap().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    RequestSummary {
        mode: Mode::Https,
        method: request["method"].as_str().unwrap().to_string(),
        host: request["host"].as_str().unwrap().to_string(),
        port: 443,
        path: request["path"].as_str().unwrap_or("/").to_string(),
        query: request["query"].as_str().unwrap_or("").to_string(),
        headers: Headers::new(headers),
        body: Body::new(
            request["body"].as_str().unwrap_or("").as_bytes().to_vec(),
            false,
        ),
        sni: None,
        remote_addr: None,
    }
}

#[test]
fn secrets_swap_vectors() {
    let vectors = common::load_vector("secrets-swap.json");
    let base_resolver = &vectors["resolver"];

    for case in vectors["cases"].as_array().unwrap() {
        let id = case["id"].as_u64().unwrap();
        let host = case["request"]["host"].as_str().unwrap();

        let mut resolver = MapResolver::from_value(base_resolver);
        if case["resolver_fails"].as_bool() == Some(true) {
            let name = case["secret"]["source"]["var"]
                .as_str()
                .or_else(|| case["secret"]["source"]["path"].as_str())
                .unwrap();
            resolver = resolver.with_failing(name);
        }

        // allowlist(host) + secrets(this case's secret).
        let specs: Vec<TransformSpec> = serde_json::from_value(json!([
            { "name": "allowlist", "config": { "domains": [host] } },
            { "name": "secrets", "config": { "secrets": [case["secret"]] } }
        ]))
        .unwrap();
        let built = build_pipeline_with_resolver(&specs, std::sync::Arc::new(resolver))
            .unwrap_or_else(|e| panic!("case {id} builds: {e}"));

        let mut summary = summary_from(&case["request"]);
        let outcome = built.pipeline.evaluate_request(&mut summary);
        let expect = &case["expect"];

        // Verdict.
        let want_verdict = expect["verdict"].as_str().unwrap();
        let secrets_trace = outcome.request_traces.iter().find(|t| t.name == "secrets");
        match want_verdict {
            "reject" => {
                assert!(
                    matches!(outcome.outcome, Outcome::Reject { .. }),
                    "case {id}: expected Reject"
                );
                assert_eq!(
                    secrets_trace.unwrap().verdict,
                    TraceVerdict::Reject,
                    "case {id}"
                );
                continue; // rejects carry no swap annotations
            }
            "continue" => {
                assert!(
                    matches!(outcome.outcome, Outcome::Continue(_)),
                    "case {id}: expected Continue"
                );
            }
            other => panic!("case {id}: unknown verdict {other:?}"),
        }

        // Mutated request fields.
        if let Some(headers) = expect["headers"].as_array() {
            let got: Vec<Vec<String>> = summary
                .headers
                .iter()
                .map(|(n, v)| vec![n.to_string(), v.to_string()])
                .collect();
            let want: Vec<Vec<String>> = headers
                .iter()
                .map(|p| vec![p[0].as_str().unwrap().into(), p[1].as_str().unwrap().into()])
                .collect();
            assert_eq!(got, want, "case {id}: headers");
        }
        if let Some(query) = expect["query"].as_str() {
            assert_eq!(summary.query, query, "case {id}: query");
        }
        if let Some(path) = expect["path"].as_str() {
            assert_eq!(summary.path, path, "case {id}: path");
        }
        if let Some(body) = expect["body"].as_str() {
            assert_eq!(
                String::from_utf8_lossy(summary.body.read()),
                body,
                "case {id}: body"
            );
        }

        // Annotations on the secrets trace.
        let trace = secrets_trace.unwrap();
        let got_annotations = Value::Object(trace.annotations.clone());
        assert_eq!(
            got_annotations, expect["annotations"],
            "case {id}: annotations"
        );

        // INV-1: the resolved value never appears in the serialized trace.
        assert!(
            !serde_json::to_string(trace).unwrap().contains("sk-real"),
            "case {id}: secret leaked into trace"
        );
    }
}
