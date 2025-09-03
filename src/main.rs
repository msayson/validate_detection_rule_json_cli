#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use std::env;

mod cli_argument_parser;
mod detection_rule_validator;
mod file_parser;

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
    let detection_rule_json: serde_json::Value =
        cli_argument_parser::parse_detection_rule_json(args)?;
    let optional_request_allow_list_json: Option<serde_json::Value> =
        cli_argument_parser::parse_request_allow_list_json(args)?;
    detection_rule_validator::validate_detection_rule_data(
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
    use std::path::Path;

    use super::*;

    const FIRST_ARG: &str = "./validate_json";

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
                file_parser::INVALID_OR_UNSAFE_PATH_MSG
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
