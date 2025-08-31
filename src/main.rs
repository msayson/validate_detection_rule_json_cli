use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const UNEXPECTED_ARGS_MSG: &str = "Received invalid arguments\n  'validate_json --help' for more information.";
const INVALID_OR_UNSAFE_PATH_MSG: &str = "Invalid or unsafe path";
const DIR_FILEPATH_MSG: &str = "Must provide a file, not a directory";

/// Prints usage instructions to stdout and exits the program.
fn print_help_and_exit() -> ! {
    println!("Usage: validate_json FILE");
    println!("   or: validate_json --help");
    println!("Validate provided file against the expected JSON Schema.");
    println!("Example: validate_json ./detection_rule.json");
    println!("\nOptions:\n    --help display help and exit");
    println!("\nArguments:");
    println!("    FILE : filepath of the file to validate");
    std::process::exit(0);
}

/// Parses and validates the file path argument from CLI input.
///
/// Expects exactly one positional argument after the executable name:
/// the path to the file to validate, or `--help`.
///
/// If `--help` is passed, it prints usage information and exits.
/// Otherwise, validates the file path points to a file, not a directory,
/// and returns the canonicalized file path.
///
/// # Arguments
/// * `args` - A slice of command-line arguments
///
/// # Returns
/// * `Ok(PathBuf)` - A canonicalized, validated file path; OR
/// * `Err(&'static str)` - An error message describing the failure
///
/// # Errors
/// Returns an error if:
/// - The number of arguments is incorrect
/// - The path is invalid or unsafe
/// - The path points to a directory
fn parse_filepath_from_args(args: &[String]) -> Result<PathBuf, &'static str> {
    // Validate provides required arguments
    if 2 != args.len() {
        return Err(UNEXPECTED_ARGS_MSG);
    }
    let first_input = &args[1];
    if first_input == "--help" {
        print_help_and_exit();
    }

    // Validate a file exists at given filepath
    let canonical_filepath = match fs::canonicalize(first_input) {
        Ok(path) => path,
        Err(_) => return Err(INVALID_OR_UNSAFE_PATH_MSG)
    };
    if canonical_filepath.is_dir() {
        return Err(DIR_FILEPATH_MSG);
    }
    Ok(canonical_filepath)
}

fn parse_detection_rule_json(args: &[String]) -> Result<serde_json::Value, String> {
    let path_buf: PathBuf = parse_filepath_from_args(&args).map_err(|err| format!("Problem parsing filepath: {}", err))?;
    let path: &Path = path_buf.as_path();
    println!("Validating file at path {}", path.display());

    let detection_rule_contents = fs::read_to_string(path).map_err(|err| format!("Error reading detection rule file: {}", err))?;
    let detection_rule_json: serde_json::Value = serde_json::from_str(&detection_rule_contents).map_err(|err| format!("Error parsing detection rule file as JSON: {}", err))?;
    Ok(detection_rule_json)
}

fn validate_detection_rule_data(detection_rule_json: &serde_json::Value) -> Result<(), String> {
    let detection_rule_schema = json!({
        "type": "object",
        "properties": {
            "id": {
                "type": "string",
                "description": "Unique identifier for the detection rule."
            },
            "name": {
                "type": "string",
                "description": "Name of the detection rule."
            },
            "description": {
                "type": "string",
                "description": "Description of the detection rule."
            },
            "version": {
                "type": "number",
                "description": "Version of the detection rule."
            }
        },
        "required": [
            "id",
            "name",
            "description",
            "version"
        ],
        "additionalProperties": false
    });

    let validator = jsonschema::validator_for(&detection_rule_schema).map_err(|err| format!("Error creating validator: {}", err))?;

    let validation_result = validator.validate(&detection_rule_json);
    if validation_result.is_err() {
        for error in validator.iter_errors(&detection_rule_json) {
            eprintln!("Error: {error}");
        }
        return Err(format!("Validation error: {}", validation_result.unwrap_err()));
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
/// - Prints usage instructions and exits with code `0` if `--help`
///     is passed as the input argument
/// - Exits with code `1` if argument or file parsing fails
fn validate_file(args: &[String]) -> Result<(), String> {
    let detection_rule_json: serde_json::Value = parse_detection_rule_json(&args)?;
    validate_detection_rule_data(&detection_rule_json)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match validate_file(&args) {
        Ok(_) => println!("Validation successful."),
        Err(err_msg) => {
            eprintln!("Failed detection rule validations, error: {}", err_msg);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_fs::TempDir;
    use assert_fs::fixture::{FileTouch, PathChild};
    use super::*;

    const FIRST_ARG: &str = "./validate_json";

    #[test]
    fn parse_filepath_from_args_requires_two_params() {
        let empty_args: Vec<String> = Vec::new();
        let single_arg_vector: Vec<String> = vec![FIRST_ARG.to_string()];
        let too_many_args_vector = vec![
            FIRST_ARG.to_string(),
            "file1.json".to_string(),
            "file2.json".to_string()
        ];
        for args_vector in [empty_args, single_arg_vector, too_many_args_vector] {
            let result = parse_filepath_from_args(&args_vector);
            assert!(matches!(result, Err(UNEXPECTED_ARGS_MSG)));
        }
    }

    #[test]
    fn parse_filepath_from_args_rejects_nonexistent_file() {
        let invalid_file_path: &str = "/not_real_dir/not_real_file.json";
        let input_args = vec![
            FIRST_ARG.to_string(),
            invalid_file_path.to_string()
        ];
        let result = parse_filepath_from_args(&input_args);
        assert!(matches!(result, Err(INVALID_OR_UNSAFE_PATH_MSG)));
    }

    #[test]
    fn parse_filepath_from_args_rejects_dir() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap().to_string();
        let input_args = vec![
            FIRST_ARG.to_string(),
            dir_path
        ];
        let result = parse_filepath_from_args(&input_args);
        assert!(matches!(result, Err(DIR_FILEPATH_MSG)));
    }

    #[test]
    fn parse_filepath_from_args_valid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.child("file.json");
        input_file.touch().unwrap();

        let input_args = vec![
            FIRST_ARG.to_string(),
            input_file.path().to_str().unwrap().to_string()
        ];
        let result = parse_filepath_from_args(&input_args);

        assert!(result.is_ok());
        let returned_path = result.unwrap();
        assert_eq!(returned_path, input_file.path().canonicalize().unwrap());
    }

    #[test]
    fn validate_file_rejects_nonexistent_file() {
        let invalid_file_path: &str = "/not_real_dir/not_real_file.json";
        let input_args = vec![
            FIRST_ARG.to_string(),
            invalid_file_path.to_string()
        ];
        let result = parse_filepath_from_args(&input_args);
        assert!(matches!(result, Err(INVALID_OR_UNSAFE_PATH_MSG)));
    }

    #[test]
    fn validate_file_passes_valid_file() {
        let file_path = Path::new("resources/test/valid_detector_rules/simple_no_op_rule.json");
        let input_args = vec![
            FIRST_ARG.to_string(),
            file_path.to_str().unwrap().to_string()
        ];
        assert!(validate_file(&input_args).is_ok());
    }

    #[test]
    fn validate_file_rejects_rule_missing_required_properties() {
        let file_path = Path::new("resources/test/invalid_detector_rules/missing_required_properties.json");
        let input_args = vec![
            FIRST_ARG.to_string(),
            file_path.to_str().unwrap().to_string()
        ];
        let result = validate_file(&input_args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert_eq!(err_msg, "Validation error: \"id\" is a required property");
    }

    #[test]
    fn validate_file_rejects_rule_with_unsupported_properties() {
        let file_path = Path::new("resources/test/invalid_detector_rules/with_unsupported_properties.json");
        let input_args = vec![
            FIRST_ARG.to_string(),
            file_path.to_str().unwrap().to_string()
        ];
        let result = validate_file(&input_args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert_eq!(err_msg, "Validation error: Additional properties are not allowed ('unsupported_property' was unexpected)");
    }
}
