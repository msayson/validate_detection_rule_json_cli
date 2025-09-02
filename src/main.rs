#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use std::env;

mod cli_argument_parser;
use cli_argument_parser::parse_detection_rule_json;

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

fn validate_detection_rule_data(
    detection_rule_json: &serde_json::Value,
    optional_request_allow_list_json: Option<&serde_json::Value>,
) -> Result<(), String> {
    validate_json_schema(DETECTION_RULE_SCHEMA, detection_rule_json, "detection rule")?;
    validate_request_allow_list_schema(optional_request_allow_list_json)
    // TODO: Validate detection rule schema against request allow-list if provided
}

/// Validates the file specified in CLI arguments.
///
/// Parses the file path and resulting file, and exits with an error message
/// if parsing fails.
///
/// # Arguments
/// * `args` - A slice of command-line arguments
///
/// # Behaviour
/// - Prints usage instructions and exits with code `0` if `--help` is passed as the input argument
/// - Exits with code `1` if argument or file parsing fails
fn validate_file(args: &[String]) -> Result<(), String> {
    let detection_rule_json: serde_json::Value = parse_detection_rule_json(args)?;
    let optional_request_allow_list_json: Option<serde_json::Value> =
        cli_argument_parser::parse_request_allow_list_json(args)?;
    validate_detection_rule_data(
        &detection_rule_json,
        optional_request_allow_list_json.as_ref(),
    )
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match validate_file(&args) {
        Ok(()) => println!("Validation successful."),
        Err(err_msg) => {
            eprintln!("Failed detection rule validations, error: {err_msg}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const FIRST_ARG: &str = "./validate_json";

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
    fn validate_file_rejects_nonexistent_file() {
        let invalid_file_path: &str = "/not_real_dir/not_real_file.json";
        let input_args = vec![FIRST_ARG.to_string(), invalid_file_path.to_string()];
        let result = validate_file(&input_args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            format!(
                "Problem parsing detection rule filepath: {}",
                cli_argument_parser::INVALID_OR_UNSAFE_PATH_MSG
            )
        );
    }

    #[test]
    fn validate_file_passes_valid_file() {
        let file_path = Path::new("resources/test/valid_detector_rules/simple_no_op_rule.json");
        let input_args = vec![
            FIRST_ARG.to_string(),
            file_path.to_str().unwrap().to_string(),
        ];
        assert!(validate_file(&input_args).is_ok());
    }

    #[test]
    fn validate_file_rejects_rule_missing_required_properties() {
        let file_path =
            Path::new("resources/test/invalid_detector_rules/missing_required_properties.json");
        let input_args = vec![
            FIRST_ARG.to_string(),
            file_path.to_str().unwrap().to_string(),
        ];
        let result = validate_file(&input_args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Validation error for detection rule: \"id\" is a required property"
        );
    }

    #[test]
    fn validate_file_rejects_rule_with_unsupported_properties() {
        let file_path =
            Path::new("resources/test/invalid_detector_rules/with_unsupported_properties.json");
        let input_args = vec![
            FIRST_ARG.to_string(),
            file_path.to_str().unwrap().to_string(),
        ];
        let result = validate_file(&input_args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Validation error for detection rule: Additional properties are not allowed ('unsupported_property' was unexpected)"
        );
    }

    #[test]
    fn validate_file_rejects_invalid_step_request_properties() {
        let file_path =
            Path::new("resources/test/invalid_detector_rules/invalid_request_properties.json");
        let input_args = vec![
            FIRST_ARG.to_string(),
            file_path.to_str().unwrap().to_string(),
        ];
        let result = validate_file(&input_args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Validation error for detection rule: Additional properties are not allowed ('args' was unexpected)"
        );
    }

    #[test]
    fn validate_file_rejects_invalid_request_allow_list() {
        let detection_rule_file_path =
            Path::new("resources/test/valid_detector_rules/simple_no_op_rule.json");
        let request_allow_list_file_path =
            Path::new("resources/test/invalid_request_allow_lists/invalid_request_schema.json");
        let input_args = vec![
            FIRST_ARG.to_string(),
            detection_rule_file_path.to_str().unwrap().to_string(),
            request_allow_list_file_path.to_str().unwrap().to_string(),
        ];
        let result = validate_file(&input_args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Validation error for request allow-list: {\"command\":\"echo\",\"exactArgs\":[\"first\",\"second\"],\"initialArgs\":[\"first\"]} is not valid under any of the schemas listed in the 'oneOf' keyword"
        );
    }

    #[test]
    fn validate_file_passes_valid_request_allow_list() {
        let detection_rule_file_path =
            Path::new("resources/test/valid_detector_rules/simple_no_op_rule.json");
        let request_allow_list_file_path = Path::new(
            "resources/test/valid_request_allow_lists/simple_cli_request_allow_list.json",
        );
        let input_args = vec![
            FIRST_ARG.to_string(),
            detection_rule_file_path.to_str().unwrap().to_string(),
            request_allow_list_file_path.to_str().unwrap().to_string(),
        ];
        assert!(validate_file(&input_args).is_ok());
    }
}
