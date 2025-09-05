use crate::api_request_validator::validate_api_request;
use crate::cli_request_validator::validate_cli_request;

const DETECTION_RULE_SCHEMA: &str = include_str!("../resources/detection_rule_schema.json");
const REQUEST_ALLOW_LIST_SCHEMA: &str = include_str!("../resources/request_allow_list_schema.json");

fn print_validation_errors(
    user_provided_json: &serde_json::Value,
    validator: &jsonschema::Validator,
) {
    eprintln!("----");
    for error in validator.iter_errors(user_provided_json) {
        eprintln!("Error: {error}");
        eprintln!("Instance path: {}", error.instance_path);
        eprintln!("Schema path: {}", error.schema_path);
        eprintln!("Keyword kind: {:?}", error.kind);
        eprintln!("----");
    }
}

fn validate_json_schema(
    schema_str: &str,
    json_value: &serde_json::Value,
    schema_type: &str,
) -> Result<(), String> {
    let schema_json: serde_json::Value = serde_json::from_str(schema_str)
        .map_err(|err| format!("Error parsing {schema_type} schema as JSON: {err}"))?;
    let validator = jsonschema::validator_for(&schema_json)
        .map_err(|err| format!("Error creating {schema_type} validator: {err}"))?;

    let validation_result = validator.validate(json_value);
    if validation_result.is_err() {
        print_validation_errors(json_value, &validator);
        return Err(format!(
            "Validation error for {}: {}",
            schema_type,
            validation_result.unwrap_err()
        ));
    }
    Ok(())
}

fn validate_request_allow_list_schema(
    optional_request_allow_list_json: Option<&serde_json::Value>,
) -> Result<(), String> {
    if optional_request_allow_list_json.is_none() {
        return Ok(());
    }

    let request_allow_list_json = optional_request_allow_list_json.unwrap();
    validate_json_schema(
        REQUEST_ALLOW_LIST_SCHEMA,
        request_allow_list_json,
        "request allow-list",
    )
}

fn validate_detection_rule_matches_request_allow_list(
    detection_rule_json: &serde_json::Value,
    optional_request_allow_list_json: Option<&serde_json::Value>,
) -> Result<(), String> {
    if optional_request_allow_list_json.is_none() {
        return Ok(());
    }
    // Validate detection rule schema against the request allow-list
    let request_allow_list_json: &serde_json::Value = optional_request_allow_list_json.unwrap();
    let allow_listed_api_requests: Option<&Vec<serde_json::Value>> = request_allow_list_json
        .get("allowedApiMethods")
        .and_then(|v| v.as_array());
    let allow_listed_cli_requests: Option<&Vec<serde_json::Value>> = request_allow_list_json
        .get("allowedCliCommands")
        .and_then(|v| v.as_array());

    // Extract each CLI command from the detection rule and verify it is allowed by the request allow-list
    let detection_rule_steps = detection_rule_json
        .get("steps")
        .unwrap()
        .as_array()
        .unwrap();
    for step in detection_rule_steps {
        let step_request_type = step.get("requestType").unwrap().as_str().unwrap();
        let request = step.get("request").unwrap();
        if step_request_type == "api" {
            validate_api_request(request, allow_listed_api_requests)?;
        } else if step_request_type == "cli" {
            validate_cli_request(request, allow_listed_cli_requests)?;
        } else {
            return Err(format!(
                "Validation error: Unsupported requestType '{step_request_type}' in detection rule step"
            ));
        }
    }
    Ok(())
}

/// Validates a detection rule JSON value against the detection rule JSON Schema and
/// checks that it adheres to the request allow-list.
///
/// # Arguments
/// * `detection_rule_json` - A JSON value representing the detection rule
/// * `optional_request_allow_list_json` - An optional JSON value representing allow-listed API and CLI requests.
///   If none, all requests that match the detection rule schema are allowed.
///
/// # Returns
/// * `Ok(())` if the detection rule is valid and adheres to the request allow-list.
/// * `Err(String)` An error message if the detection rule is invalid or does not adhere
///   to the request allow-list.
///
/// # Errors
/// Returns an error if:
/// * The detection rule does not conform to the detection rule JSON Schema.
/// * The request allow-list is provided and does not conform to the request allow-list JSON Schema.
/// * The detection rule contains a CLI request that is not allowed by the request allow-list.
pub fn validate_detection_rule_data(
    detection_rule_json: &serde_json::Value,
    optional_request_allow_list_json: Option<&serde_json::Value>,
) -> Result<(), String> {
    validate_json_schema(DETECTION_RULE_SCHEMA, detection_rule_json, "detection rule")?;
    validate_request_allow_list_schema(optional_request_allow_list_json)?;

    validate_detection_rule_matches_request_allow_list(
        detection_rule_json,
        optional_request_allow_list_json,
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::file_parser::{parse_filepath, parse_json_file};

    fn parse_json_from_filepath(
        input_filepath: &str,
        file_type: &str,
    ) -> Result<serde_json::Value, String> {
        let path_buf: PathBuf = parse_filepath(input_filepath)
            .map_err(|err| format!("Problem parsing {file_type} filepath: {err}"))?;
        parse_json_file(&path_buf, file_type)
    }

    #[test]
    fn detection_rule_schema_is_valid() {
        let detection_rule_schema_json: serde_json::Value =
            serde_json::from_str(DETECTION_RULE_SCHEMA)
                .expect("Failed to parse detection rule schema as JSON");
        let validation_result =
            jsonschema::draft202012::meta::validate(&detection_rule_schema_json);
        assert!(validation_result.is_ok());
    }

    #[test]
    fn request_allow_list_schema_is_valid() {
        let request_allow_list_schema_json: serde_json::Value =
            serde_json::from_str(REQUEST_ALLOW_LIST_SCHEMA)
                .expect("Failed to parse request allow-list schema as JSON");
        let validation_result =
            jsonschema::draft202012::meta::validate(&request_allow_list_schema_json);
        assert!(validation_result.is_ok());
    }

    #[test]
    fn validate_detection_rule_data_passes_valid_file() {
        let detection_rule_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/valid_detector_rules/multiple_request_types_rule.json",
            "detection rule",
        )
        .unwrap();

        let result = validate_detection_rule_data(&detection_rule_json, None);
        assert!(
            result.is_ok(),
            "Unexpected validation error: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn validate_detection_rule_data_rejects_invalid_step_request_properties() {
        let detection_rule_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/invalid_detector_rules/invalid_request_properties.json",
            "detection rule",
        )
        .unwrap();

        let result = validate_detection_rule_data(&detection_rule_json, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Validation error for detection rule: Additional properties are not allowed ('args' was unexpected)"
        );
    }

    #[test]
    fn validate_detection_rule_data_rejects_rule_with_unsupported_properties() {
        let detection_rule_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/invalid_detector_rules/with_unsupported_properties.json",
            "detection rule",
        )
        .unwrap();

        let result = validate_detection_rule_data(&detection_rule_json, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Validation error for detection rule: Additional properties are not allowed ('unsupported_property' was unexpected)"
        );
    }

    #[test]
    fn validate_detection_rule_data_rejects_invalid_request_allow_list() {
        let detection_rule_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/valid_detector_rules/simple_no_op_rule.json",
            "detection rule",
        )
        .unwrap();
        let request_allow_list_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/invalid_request_allow_lists/invalid_request_schema.json",
            "request allow-list",
        )
        .unwrap();

        let result =
            validate_detection_rule_data(&detection_rule_json, Some(&request_allow_list_json));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Validation error for request allow-list: {\"command\":\"echo\",\"exactArgs\":[\"first\",\"second\"],\"initialArgs\":[\"first\"]} is not valid under any of the schemas listed in the 'anyOf' keyword"
        );
    }

    #[test]
    fn validate_detection_rule_data_passes_valid_request_allow_list() {
        let detection_rule_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/valid_detector_rules/multiple_request_types_rule.json",
            "detection rule",
        )
        .unwrap();
        let request_allow_list_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/valid_request_allow_lists/multiple_request_types_allow_list.json",
            "request allow-list",
        )
        .unwrap();

        let result =
            validate_detection_rule_data(&detection_rule_json, Some(&request_allow_list_json));
        assert!(
            result.is_ok(),
            "Unexpected validation error: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn validate_detection_rule_data_rejects_unallowed_cli_command() {
        let detection_rule_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/valid_detector_rules/multiple_cli_requests_rule.json",
            "detection rule",
        )
        .unwrap();
        let request_allow_list_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/valid_request_allow_lists/exact_cli_args_allow_list.json",
            "request allow-list",
        )
        .unwrap();

        let result =
            validate_detection_rule_data(&detection_rule_json, Some(&request_allow_list_json));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Validation error: CLI command 'ls' is not allowed, allow-listed CLI commands: [\"echo\"]"
        );
    }

    #[test]
    fn validate_detection_rule_data_rejects_unallowed_api_request() {
        let detection_rule_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/valid_detector_rules/multiple_request_types_rule.json",
            "detection rule",
        )
        .unwrap();
        let request_allow_list_json: serde_json::Value = serde_json::json!({
            "id": "Test::RequestAllowList",
            "description": "This is a test request allow-list.",
            "allowedApiMethods": [
                {
                    "method": "GET",
                    "url": "/api/v1/resource"
                }
            ],
            "allowedCliCommands": [
                {
                    "command": "echo"
                },
                {
                    "command": "aws",
                    "initialArgs": [
                        "s3",
                        "ls"
                    ]
                },
                {
                    "command": "aws",
                    "initialArgs": [
                        "dynamodb",
                        "list-tables"
                    ]
                }
            ]
        });

        let result =
            validate_detection_rule_data(&detection_rule_json, Some(&request_allow_list_json));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Validation error: API request ApiRequest {\n    method: \"POST\",\n    url: \"https://dynamodb.eu-west-2.amazonaws.com\",\n} is not allowed by the request allow-list"
        );
    }
}
