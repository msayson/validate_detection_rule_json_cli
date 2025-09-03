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

pub fn validate_detection_rule_data(
    detection_rule_json: &serde_json::Value,
    optional_request_allow_list_json: Option<&serde_json::Value>,
) -> Result<(), String> {
    validate_json_schema(DETECTION_RULE_SCHEMA, detection_rule_json, "detection rule")?;
    validate_request_allow_list_schema(optional_request_allow_list_json)
    // TODO: Validate detection rule schema against request allow-list if provided
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
            "resources/test/valid_detector_rules/simple_no_op_rule.json",
            "detection rule",
        )
        .unwrap();

        let result = validate_detection_rule_data(&detection_rule_json, None);
        assert!(result.is_ok());
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
            "Validation error for request allow-list: {\"command\":\"echo\",\"exactArgs\":[\"first\",\"second\"],\"initialArgs\":[\"first\"]} is not valid under any of the schemas listed in the 'oneOf' keyword"
        );
    }
}
