#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use std::env;

mod cli_argument_parser;
use cli_argument_parser::parse_detection_rule_json;

const DETECTION_RULE_SCHEMA: &str = include_str!("../resources/detection_rule_schema.json");

fn print_validation_errors(
    detection_rule_json: &serde_json::Value,
    validator: &jsonschema::Validator,
) {
    eprintln!("----");
    for error in validator.iter_errors(detection_rule_json) {
        eprintln!("Error: {error}");
        eprintln!("Instance path: {}", error.instance_path);
        eprintln!("Schema path: {}", error.schema_path);
        eprintln!("Keyword kind: {:?}", error.kind);
        eprintln!("----");
    }
}

fn validate_detection_rule_data(detection_rule_json: &serde_json::Value) -> Result<(), String> {
    let detection_rule_schema_json: serde_json::Value = serde_json::from_str(DETECTION_RULE_SCHEMA)
        .map_err(|err| format!("Error parsing detection rule schema as JSON: {err}"))?;
    let validator = jsonschema::validator_for(&detection_rule_schema_json)
        .map_err(|err| format!("Error creating validator: {err}"))?;

    let validation_result = validator.validate(detection_rule_json);
    if validation_result.is_err() {
        print_validation_errors(detection_rule_json, &validator);
        return Err(format!(
            "Validation error: {}",
            validation_result.unwrap_err()
        ));
    }
    Ok(())
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
    validate_detection_rule_data(&detection_rule_json)
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
    fn validate_file_rejects_nonexistent_file() {
        let invalid_file_path: &str = "/not_real_dir/not_real_file.json";
        let input_args = vec![FIRST_ARG.to_string(), invalid_file_path.to_string()];
        let result = validate_file(&input_args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            format!(
                "Problem parsing filepath: {}",
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
            "Validation error: \"id\" is a required property"
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
            "Validation error: Additional properties are not allowed ('unsupported_property' was unexpected)"
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
            "Validation error: Additional properties are not allowed ('args' was unexpected)"
        );
    }
}
