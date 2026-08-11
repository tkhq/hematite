//! Building a pipeline from configuration (the `transforms:` list of
//! Part 09, as data). Validation is reject-at-load, never at request time.

use std::fmt;

use serde::Deserialize;
use serde_json::Value;

use crate::matcher::{
    Cidr, DomainGlob, HeaderNameEntry, HostClause, MatchConfigError, PathGlob, Rule,
};
use crate::pipeline::{Pipeline, Transform};
use crate::secret::{SecretResolver, SourceKind, SourceRef};
use crate::secrets::{SecretSpec, Secrets};
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretsConfig {
    secrets: Vec<SecretEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretEntry {
    source: SourceSpec,
    proxy_value: String,
    #[serde(default)]
    match_headers: Option<Vec<String>>,
    #[serde(default)]
    match_query: bool,
    #[serde(default)]
    match_path: bool,
    #[serde(default)]
    match_body: bool,
    #[serde(default)]
    require: bool,
    rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "lowercase")]
enum SourceSpec {
    Env {
        var: String,
        #[serde(default)]
        json_key: Option<String>,
    },
    File {
        path: String,
        // Accepted and validated as part of the schema; TTL-based refresh
        // is a runtime concern layered above build-time resolution and is
        // not yet consumed by the kernel (see resolver.rs).
        #[serde(default)]
        #[allow(dead_code)]
        ttl: Option<String>,
        #[serde(default)]
        #[allow(dead_code)]
        failure_ttl: Option<String>,
        #[serde(default)]
        json_key: Option<String>,
    },
}

impl SourceSpec {
    fn into_ref(self) -> SourceRef {
        match self {
            SourceSpec::Env { var, json_key } => {
                SourceRef { kind: SourceKind::Env { var }, json_key }
            }
            SourceSpec::File { path, json_key, .. } => {
                SourceRef { kind: SourceKind::File { path }, json_key }
            }
        }
    }
}

fn build_secret_spec(entry: &SecretEntry) -> Result<SecretSpec, ConfigError> {
    // `match_headers: []`/absent = scan all; a populated list compiles as
    // header-name entries (regex allowed, Part 02 §5).
    let match_headers = match &entry.match_headers {
        None => None,
        Some(list) if list.is_empty() => None,
        Some(list) => Some(
            list.iter()
                .map(|h| HeaderNameEntry::parse(h, true))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };
    // Part 04 §3.2: match_path requires an unreserved-only proxy_value so
    // the raw-path scan cannot miss an encoded token.
    if entry.match_path
        && !entry
            .proxy_value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(ConfigError(
            "secrets: proxy_value must be RFC 3986 unreserved-only when match_path is set".into(),
        ));
    }
    Ok(SecretSpec {
        source: entry.source.clone().into_ref(),
        proxy_value: entry.proxy_value.clone(),
        match_headers,
        match_query: entry.match_query,
        match_path: entry.match_path,
        match_body: entry.match_body,
        require: entry.require,
        rules: compile_rules(&entry.rules)?,
    })
}

fn build_transform(
    spec: &TransformSpec,
    resolver: Option<&dyn SecretResolver>,
) -> Result<Box<dyn Transform>, ConfigError> {
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
        "secrets" => {
            let resolver = resolver.ok_or_else(|| {
                ConfigError(
                    "the `secrets` transform is L3; build with a SecretResolver \
                     (build_pipeline_with_resolver)"
                        .into(),
                )
            })?;
            let c: SecretsConfig = deser("secrets", &spec.config)?;
            if c.secrets.is_empty() {
                return Err(ConfigError("secrets: at least one secret required".into()));
            }
            let specs = c
                .secrets
                .iter()
                .map(build_secret_spec)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Box::new(Secrets::build(specs, resolver)))
        }
        other => Err(ConfigError(format!(
            "unknown transform {other:?}: the v1 registry is closed (Part 03 §5)"
        ))),
    }
}

/// Build the pipeline from the `transforms:` list, in file order
/// (Part 03 §1: order is semantic; the kernel never reorders). L0 entry:
/// a `secrets` transform fails without a resolver. Use
/// `build_pipeline_with_resolver` for L3.
pub fn build_pipeline(specs: &[TransformSpec]) -> Result<BuiltPipeline, ConfigError> {
    build_pipeline_inner(specs, None)
}

/// L3 entry: resolves `secrets` sources through `resolver` at build time
/// (Part 01 §5, Part 04 §3).
pub fn build_pipeline_with_resolver(
    specs: &[TransformSpec],
    resolver: &dyn SecretResolver,
) -> Result<BuiltPipeline, ConfigError> {
    build_pipeline_inner(specs, Some(resolver))
}

fn build_pipeline_inner(
    specs: &[TransformSpec],
    resolver: Option<&dyn SecretResolver>,
) -> Result<BuiltPipeline, ConfigError> {
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
    // Part 04 §6: body_capture must precede a body-matching secrets entry.
    body_capture_ordering_lint(specs, &mut warnings);

    let transforms = specs
        .iter()
        .map(|s| build_transform(s, resolver))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BuiltPipeline { pipeline: Pipeline::new(transforms), warnings })
}

/// Warn when `body_capture` follows a `secrets` entry with
/// `match_body: true` (Part 04 §6, 09 §3).
fn body_capture_ordering_lint(specs: &[TransformSpec], warnings: &mut Vec<String>) {
    let body_matching_secrets = specs.iter().position(|s| {
        s.name == "secrets"
            && s.config
                .get("secrets")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().any(|e| e.get("match_body").and_then(|b| b.as_bool()) == Some(true)))
                .unwrap_or(false)
    });
    let body_capture_pos = specs.iter().position(|s| s.name == "body_capture");
    if let (Some(secrets_i), Some(capture_i)) = (body_matching_secrets, body_capture_pos) {
        if capture_i > secrets_i {
            warnings.push(
                "body_capture follows a secrets entry with match_body: true; \
                 the log will hold real credentials (Part 04 §6)"
                    .into(),
            );
        }
    }
}
