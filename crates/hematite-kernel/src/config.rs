//! Building a pipeline from configuration (the `transforms:` list of
//! Part 09, as data). Validation is reject-at-load, never at request time.

use std::fmt;

use serde::Deserialize;
use serde_json::Value;

use crate::matcher::{
    Cidr, DomainGlob, HeaderNameEntry, HostClause, MatchConfigError, PathGlob, Rule,
};
use crate::pipeline::{Pipeline, Transform};
use crate::transforms::{Allowlist, Annotate, AnnotateGroup, BodyCaptureTransform, HeaderAllowlist};

#[derive(Debug)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "config error: {}", self.0)
    }
}

impl From<MatchConfigError> for ConfigError {
    fn from(e: MatchConfigError) -> Self {
        ConfigError(e.to_string())
    }
}

/// One entry of the `transforms:` list.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformSpec {
    pub name: String,
    #[serde(default)]
    pub config: Value,
}

/// A built pipeline plus validation lint warnings (Part 09 §3: the ordering
/// lints warn, they do not fail).
pub struct BuiltPipeline {
    pub pipeline: Pipeline,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    host: String,
    #[serde(default)]
    methods: Option<Vec<String>>,
    #[serde(default)]
    paths: Option<Vec<String>>,
}

fn compile_rules(specs: &[RuleSpec]) -> Result<Vec<Rule>, ConfigError> {
    if specs.is_empty() {
        // Part 02 §1: an empty rule list is a config error unless a part
        // explicitly gives it meaning ("absent = all" is expressed by
        // omitting the key, not by an empty list).
        return Err(ConfigError("empty rule list".into()));
    }
    specs
        .iter()
        .map(|s| {
            Ok(Rule {
                host: HostClause::parse(&s.host)?,
                methods: s
                    .methods
                    .as_ref()
                    .map(|m| m.iter().map(|x| x.to_ascii_uppercase()).collect()),
                paths: s
                    .paths
                    .as_ref()
                    .map(|p| p.iter().map(|x| PathGlob::parse(x)).collect())
                    .transpose()?,
            })
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowlistConfig {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default)]
    warn: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnotateConfig {
    annotations: Vec<AnnotateGroupSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnotateGroupSpec {
    rules: Vec<RuleSpec>,
    headers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderAllowlistConfig {
    headers: Vec<String>,
    #[serde(default)]
    rules: Option<Vec<RuleSpec>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyCaptureConfig {
    max_request_body_bytes: usize,
    rules: Vec<RuleSpec>,
}

fn deser<T: serde::de::DeserializeOwned>(name: &str, config: &Value) -> Result<T, ConfigError> {
    serde_json::from_value(config.clone())
        .map_err(|e| ConfigError(format!("transform {name:?}: {e}")))
}

fn build_transform(spec: &TransformSpec) -> Result<Box<dyn Transform>, ConfigError> {
    match spec.name.as_str() {
        "allowlist" => {
            let c: AllowlistConfig = deser("allowlist", &spec.config)?;
            if c.domains.is_empty() && c.cidrs.is_empty() {
                return Err(ConfigError(
                    "allowlist: at least one of domains/cidrs must be non-empty (Part 04 §1)".into(),
                ));
            }
            Ok(Box::new(Allowlist {
                domains: c
                    .domains
                    .iter()
                    .map(|d| DomainGlob::parse(d))
                    .collect::<Result<_, _>>()?,
                cidrs: c.cidrs.iter().map(|x| Cidr::parse(x)).collect::<Result<_, _>>()?,
                warn: c.warn,
            }))
        }
        "annotate" => {
            let c: AnnotateConfig = deser("annotate", &spec.config)?;
            let groups = c
                .annotations
                .iter()
                .map(|g| {
                    let headers = g
                        .headers
                        .iter()
                        .map(|h| match HeaderNameEntry::parse(h, false)? {
                            HeaderNameEntry::Literal(l) => Ok(l),
                            HeaderNameEntry::Regex(_) => unreachable!("allow_regex = false"),
                        })
                        .collect::<Result<Vec<_>, MatchConfigError>>()?;
                    Ok(AnnotateGroup { rules: compile_rules(&g.rules)?, headers })
                })
                .collect::<Result<Vec<_>, ConfigError>>()?;
            Ok(Box::new(Annotate { groups }))
        }
        "header_allowlist" => {
            let c: HeaderAllowlistConfig = deser("header_allowlist", &spec.config)?;
            if c.headers.is_empty() {
                return Err(ConfigError("header_allowlist: headers must be non-empty".into()));
            }
            Ok(Box::new(HeaderAllowlist {
                entries: c
                    .headers
                    .iter()
                    .map(|h| HeaderNameEntry::parse(h, true))
                    .collect::<Result<_, _>>()?,
                rules: c.rules.as_deref().map(compile_rules).transpose()?,
            }))
        }
        "body_capture" => {
            let c: BodyCaptureConfig = deser("body_capture", &spec.config)?;
            Ok(Box::new(BodyCaptureTransform {
                max_request_body_bytes: c.max_request_body_bytes,
                rules: compile_rules(&c.rules)?,
            }))
        }
        "secrets" => Err(ConfigError(
            "the `secrets` transform (Part 04 §3) is L3 and not implemented at this level".into(),
        )),
        other => Err(ConfigError(format!(
            "unknown transform {other:?}: the v1 registry is closed (Part 03 §5)"
        ))),
    }
}

/// Build the pipeline from the `transforms:` list, in file order
/// (Part 03 §1: order is semantic; the kernel never reorders).
pub fn build_pipeline(specs: &[TransformSpec]) -> Result<BuiltPipeline, ConfigError> {
    let allowlist_pos = specs.iter().position(|s| s.name == "allowlist");
    // Part 04 §1: default-deny is structural — a config with no allowlist
    // fails validation.
    if allowlist_pos.is_none() {
        return Err(ConfigError(
            "no allowlist transform: default-deny is structural (Part 04 §1)".into(),
        ));
    }

    let mut warnings = Vec::new();
    if allowlist_pos != Some(0) {
        warnings.push("allowlist is present but not first in the pipeline (Part 04 §1)".into());
    }

    let transforms = specs.iter().map(build_transform).collect::<Result<Vec<_>, _>>()?;
    Ok(BuiltPipeline { pipeline: Pipeline::new(transforms), warnings })
}
