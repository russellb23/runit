//! Inbound connector catalog.
//!
//! The catalog lives in `connectors/catalog.json` (the same file is checked by
//! `frontend/scripts/connector-catalog.test.js`). Each connector declares:
//! - config fields: required or optional, with defaults the server fills in when they are missing;
//! - payload fields: how the source system's webhook payload maps onto a relay. Fields marked
//!   `mandatory` (the ones that feed `dedup_key` and `title`) must always be present and required.
//!
//! Only inbound connections (a source system sending alerts to RelayOps) exist for now. Outbound
//! notification channels are configured per responder under Users & channels.

use serde::{ Deserialize, Serialize };
use serde_json::{ json, Value };
use std::sync::OnceLock;

/// Connector keys from earlier releases that were outbound or notification connectors. Existing
/// records are kept (and can be deleted) but can no longer be created, changed, or validated.
pub const LEGACY_OUTBOUND: [&str; 6] = [
    "smtp_email",
    "signed_webhook",
    "slack",
    "microsoft_teams",
    "jira",
    "servicenow",
];

/// Relay fields a payload path can feed.
pub const MAPS_TO: [&str; 7] = [
    "dedup_key",
    "title",
    "description",
    "severity",
    "service",
    "status",
    "url",
];

#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigFieldDef {
    pub key: String,
    pub label: String,
    /// "text" or "select"
    pub kind: String,
    pub required: bool,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub options: Vec<String>,
    #[serde(default)]
    pub help: String,
    #[serde(default)]
    pub placeholder: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PayloadFieldDef {
    pub path: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub required: bool,
    #[serde(default)]
    pub mandatory: bool,
    #[serde(default)]
    pub maps_to: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SeverityMapEntry {
    pub from: String,
    pub to: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ConnectorDefinition {
    pub key: String,
    pub name: String,
    pub category: String,
    pub direction: String,
    pub supported: bool,
    pub summary: String,
    pub format: String,
    pub config_fields: Vec<ConfigFieldDef>,
    pub payload_fields: Vec<PayloadFieldDef>,
    #[serde(default)]
    pub severity_map: Vec<SeverityMapEntry>,
    #[serde(default)]
    pub sender_template: Option<String>,
    pub sample_payload: Value,
    /// Config field keys plus `credential_reference`; kept for clients of the earlier catalog shape.
    #[serde(default)]
    pub fields: Vec<String>,
}

#[derive(Deserialize)]
struct CatalogFile {
    connectors: Vec<ConnectorDefinition>,
}

static CATALOG: OnceLock<Vec<ConnectorDefinition>> = OnceLock::new();

pub fn catalog() -> &'static [ConnectorDefinition] {
    CATALOG.get_or_init(|| {
        let file: CatalogFile = serde_json
            ::from_str(include_str!("connectors/catalog.json"))
            .expect("connectors/catalog.json must be valid");
        file.connectors
            .into_iter()
            .map(|mut connector| {
                connector.fields = connector.config_fields
                    .iter()
                    .map(|f| f.key.clone())
                    .chain(std::iter::once("credential_reference".to_string()))
                    .collect();
                connector
            })
            .collect()
    })
}

pub fn find(key: &str) -> Option<&'static ConnectorDefinition> {
    catalog()
        .iter()
        .find(|c| c.key == key)
}

/// Fills connector defaults and enforces required and mandatory fields. Returns the configuration to store.
pub fn normalize_configuration(
    connector: &ConnectorDefinition,
    configuration: &Value
) -> Result<Value, String> {
    let mut config = configuration
        .as_object()
        .cloned()
        .ok_or_else(|| "configuration must be a JSON object".to_string())?;

    for field in &connector.config_fields {
        let supplied = config
            .get(&field.key)
            .and_then(Value::as_str)
            .map(|v| v.trim().to_string())
            .unwrap_or_default();
        let value = if supplied.is_empty() {
            field.default.clone().unwrap_or_default()
        } else {
            supplied
        };
        if value.is_empty() {
            if field.required {
                return Err(format!("{} is required", field.label));
            }
            config.remove(&field.key);
            continue;
        }
        if value.chars().count() > 200 {
            return Err(format!("{} must be at most 200 characters", field.label));
        }
        if field.kind == "select" && !field.options.iter().any(|option| *option == value) {
            return Err(format!("{} must be one of: {}", field.label, field.options.join(", ")));
        }
        config.insert(field.key.clone(), Value::String(value));
    }

    match config.get("payload_fields") {
        None => {
            let defaults: Vec<Value> = connector.payload_fields
                .iter()
                .map(
                    |f|
                        json!({ "path": f.path, "type": f.field_type, "required": f.required, "maps_to": f.maps_to, "description": f.description })
                )
                .collect();
            config.insert("payload_fields".to_string(), Value::Array(defaults));
        }
        Some(Value::Array(existing)) => {
            for mandatory in connector.payload_fields.iter().filter(|f| f.mandatory) {
                let present = existing.iter().any(|entry| {
                    entry.get("maps_to").and_then(Value::as_str) ==
                        Some(mandatory.maps_to.as_str()) &&
                        entry.get("required").and_then(Value::as_bool) == Some(true) &&
                        entry
                            .get("path")
                            .and_then(Value::as_str)
                            .is_some_and(|p| !p.trim().is_empty())
                });
                if !present {
                    return Err(
                        format!(
                            "the mandatory payload field for {} (default path {}) must be present and required",
                            mandatory.maps_to,
                            mandatory.path
                        )
                    );
                }
            }
        }
        // A payload_fields value of the wrong shape is reported by the payload field validation.
        Some(_) => {}
    }
    Ok(Value::Object(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a dot path, decoding JSON strings met along the way (mirrors `resolvePath` in connectorMapping.ts).
    fn resolve(root: &Value, path: &str) -> Option<Value> {
        let mut current = root.clone();
        for part in path.split('.') {
            if let Value::String(text) = &current {
                match serde_json::from_str::<Value>(text) {
                    Ok(parsed) if parsed.is_object() || parsed.is_array() => {
                        current = parsed;
                    }
                    _ => {
                        return None;
                    }
                }
            }
            current = match &current {
                Value::Array(items) => items.get(part.parse::<usize>().ok()?)?.clone(),
                Value::Object(map) => map.get(part)?.clone(),
                _ => {
                    return None;
                }
            };
            if current.is_null() {
                return None;
            }
        }
        Some(current)
    }

    #[test]
    fn catalog_is_inbound_only_with_unique_keys() {
        let all = catalog();
        assert!(all.len() >= 15);
        let mut keys: Vec<&str> = all
            .iter()
            .map(|c| c.key.as_str())
            .collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), all.len());
        assert!(all.iter().all(|c| c.direction == "inbound"));
        assert!(all.iter().all(|c| !LEGACY_OUTBOUND.contains(&c.key.as_str())));
        assert!(find("alert_api").is_some_and(|c| c.supported));
    }

    #[test]
    fn every_connector_has_mandatory_dedup_key_and_title() {
        for connector in catalog() {
            for target in ["dedup_key", "title"] {
                assert!(
                    connector.payload_fields
                        .iter()
                        .any(|f| f.maps_to == target && f.mandatory && f.required),
                    "{} lacks a mandatory {target}",
                    connector.key
                );
            }
            assert!(connector.payload_fields.iter().all(|f| MAPS_TO.contains(&f.maps_to.as_str())));
        }
    }

    #[test]
    fn sample_payloads_contain_every_defined_path() {
        for connector in catalog() {
            for field in &connector.payload_fields {
                assert!(
                    resolve(&connector.sample_payload, &field.path).is_some(),
                    "{}: {} not found in sample",
                    connector.key,
                    field.path
                );
            }
        }
    }

    #[test]
    fn defaults_are_filled_in() {
        let connector = find("prometheus_alertmanager").unwrap();
        let config = normalize_configuration(connector, &json!({})).unwrap();
        assert_eq!(config["source"], "alertmanager");
        assert_eq!(config["default_severity"], "warning");
        assert_eq!(
            config["payload_fields"].as_array().unwrap().len(),
            connector.payload_fields.len()
        );
    }

    #[test]
    fn supplied_values_win_and_selects_are_checked() {
        let connector = find("datadog").unwrap();
        let config = normalize_configuration(
            connector,
            &json!({ "source": "dd-prod", "site": "datadoghq.eu" })
        ).unwrap();
        assert_eq!(config["source"], "dd-prod");
        assert_eq!(config["site"], "datadoghq.eu");
        assert!(
            normalize_configuration(connector, &json!({ "default_severity": "urgent" })).is_err()
        );
        assert!(normalize_configuration(connector, &json!({ "site": "example.com" })).is_err());
    }

    #[test]
    fn mandatory_payload_fields_cannot_be_removed_or_made_optional() {
        let connector = find("grafana").unwrap();
        let only_optional =
            json!({ "payload_fields": [{ "path": "alerts.0.labels.service", "type": "string", "required": false, "maps_to": "service" }] });
        assert!(normalize_configuration(connector, &only_optional).is_err());
        let mut fields: Vec<Value> = connector.payload_fields
            .iter()
            .map(
                |f|
                    json!({ "path": f.path, "type": f.field_type, "required": f.required, "maps_to": f.maps_to })
            )
            .collect();
        assert!(
            normalize_configuration(connector, &json!({ "payload_fields": fields.clone() })).is_ok()
        );
        fields[0]["required"] = json!(false);
        assert!(normalize_configuration(connector, &json!({ "payload_fields": fields })).is_err());
    }

    #[test]
    fn a_mandatory_path_may_be_changed_but_not_blanked() {
        let connector = find("prometheus_alertmanager").unwrap();
        let mut fields: Vec<Value> = connector.payload_fields
            .iter()
            .map(
                |f|
                    json!({ "path": f.path, "type": f.field_type, "required": f.required, "maps_to": f.maps_to })
            )
            .collect();
        let title = fields
            .iter()
            .position(|f| f["maps_to"] == "title")
            .unwrap();
        fields[title]["path"] = json!("alerts.0.labels.name");
        assert!(
            normalize_configuration(connector, &json!({ "payload_fields": fields.clone() })).is_ok()
        );
        fields[title]["path"] = json!("  ");
        assert!(normalize_configuration(connector, &json!({ "payload_fields": fields })).is_err());
    }

    #[test]
    fn non_object_configuration_is_rejected() {
        assert!(normalize_configuration(find("alert_api").unwrap(), &json!([])).is_err());
    }
}
