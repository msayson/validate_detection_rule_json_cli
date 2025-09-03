use std::fs;
use std::path::{Path, PathBuf};

use crate::file_parser::{parse_filepath, parse_json_file};

const UNEXPECTED_ARGS_MSG: &str =
    "Received invalid arguments\n  'validate_detection_rule_json --help' for more information.";

/// Prints usage instructions to stdout and exits the program.
fn print_help_and_exit() -> ! {
    println!(
        "Usage: validate_detection_rule_json DETECTION_RULE_FILEPATH [REQUEST_ALLOW_LIST_FILEPATH]"
    );
    println!("   or: validate_detection_rule_json --help");
    println!("\nValidate provided detection rule against the expected JSON Schema.");
    println!("\nExample: validate_detection_rule_json ./detection_rule.json");
    println!(
        "     or: validate_detection_rule_json ./detection_rule.json ./request_allow_list.json"
    );
    println!("\nOptions:\n    --help display help and exit");
    println!("\nArguments:");
    println!("    DETECTION_RULE_FILEPATH : filepath of the detection rule to validate");
    println!(
        "    REQUEST_ALLOW_LIST_FILEPATH : filepath of the request allow-list to enforce on the detection rule"
    );
    std::process::exit(0);
}

fn parse_detection_rule_filepath_from_args(args: &[String]) -> Result<PathBuf, &'static str> {
    if args.len() < 2 || args.len() > 3 {
        return Err(UNEXPECTED_ARGS_MSG);
    }
    let first_input = &args[1];
    if first_input == "--help" {
        print_help_and_exit();
    }
    parse_filepath(first_input)
}

fn parse_request_allow_list_filepath_from_args(
    args: &[String],
) -> Result<Option<PathBuf>, &'static str> {
    if 3 != args.len() {
        return Ok(None);
    }
    let second_input = &args[2];
    if second_input == "--help" {
        print_help_and_exit();
    }
    parse_filepath(second_input).map(Some)
}

/// Parses the provided CLI arguments and returns the contents of the file
/// pointed to by the first argument as a `serde_json::Value`.
///
/// # Arguments
/// * `args` - A slice of command-line arguments
///
/// # Returns
/// * `Ok(serde_json::Value)` - The parsed JSON value; OR
/// * `Err(String)` - An error message describing the failure
///
/// # Errors
/// Returns an error if:
/// - The number of arguments is incorrect
/// - The path is invalid or unsafe
/// - The path points to a directory
/// - The file cannot be read
/// - The file cannot be parsed as JSON
pub fn parse_detection_rule_json(args: &[String]) -> Result<serde_json::Value, String> {
    let path_buf: PathBuf = parse_detection_rule_filepath_from_args(args)
        .map_err(|err| format!("Problem parsing detection rule filepath: {err}"))?;
    parse_json_file(&path_buf, "detection rule")
}

/// Parses the provided CLI arguments and returns the contents of the file
/// pointed to by the second argument as an `Option<serde_json::Value>`.
///
/// # Arguments
/// * `args` - A slice of command-line arguments
///
/// # Returns
/// * `Ok(None)` - There is no valid second argument;
/// * `Ok(Some(serde_json::Value))` - The parsed JSON value; OR
/// * `Err(String)` - An error message describing the failure
///
/// # Errors
/// Returns an error if:
/// - The number of arguments is incorrect
/// - The path is invalid or unsafe
/// - The path points to a directory
/// - The file cannot be read
/// - The file cannot be parsed as JSON
pub fn parse_request_allow_list_json(args: &[String]) -> Result<Option<serde_json::Value>, String> {
    let optional_path_buf: Option<PathBuf> = parse_request_allow_list_filepath_from_args(args)
        .map_err(|err| format!("Problem parsing request allow-list filepath: {err}"))?;
    if optional_path_buf.is_none() {
        return Ok(None);
    }
    let path_buf = optional_path_buf.as_ref().unwrap();
    let path: &Path = path_buf.as_path();
    println!("Parsing request allow-list file at path {}", path.display());

    let request_allow_list_contents = fs::read_to_string(path)
        .map_err(|err| format!("Error reading request allow-list file: {err}"))?;
    let request_allow_list_json: serde_json::Value =
        serde_json::from_str(&request_allow_list_contents)
            .map_err(|err| format!("Error parsing request allow-list file as JSON: {err}"))?;
    Ok(Some(request_allow_list_json))
}

#[cfg(test)]
mod tests {
    use assert_fs::TempDir;
    use assert_fs::fixture::{FileTouch, PathChild};

    use super::*;
    use crate::file_parser::{DIR_FILEPATH_MSG, INVALID_OR_UNSAFE_PATH_MSG};

    const FIRST_ARG: &str = "./validate_detection_rule_json";

    #[test]
    fn parse_detection_rule_json_rejects_invalid_number_args() {
        let empty_args: Vec<String> = Vec::new();
        let single_arg_vector: Vec<String> = vec![FIRST_ARG.to_string()];
        let too_many_args_vector = vec![
            FIRST_ARG.to_string(),
            "file1.json".to_string(),
            "file2.json".to_string(),
            "file3.json".to_string(),
        ];
        for args_vector in [empty_args, single_arg_vector, too_many_args_vector] {
            let result = parse_detection_rule_json(&args_vector);
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                format!("Problem parsing detection rule filepath: {UNEXPECTED_ARGS_MSG}")
            );
        }
    }

    #[test]
    fn parse_detection_rule_json_rejects_nonexistent_file() {
        let invalid_file_path: &str = "/not_real_dir/not_real_file.json";
        let input_args = vec![FIRST_ARG.to_string(), invalid_file_path.to_string()];
        let result = parse_detection_rule_json(&input_args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            format!("Problem parsing detection rule filepath: {INVALID_OR_UNSAFE_PATH_MSG}")
        );
    }

    #[test]
    fn parse_detection_rule_json_rejects_dir() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap().to_string();
        let input_args = vec![FIRST_ARG.to_string(), dir_path];
        let result = parse_detection_rule_json(&input_args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            format!("Problem parsing detection rule filepath: {DIR_FILEPATH_MSG}",)
        );
    }

    #[test]
    fn parse_detection_rule_json_valid_file() {
        let file_path = Path::new("resources/test/valid_detector_rules/simple_no_op_rule.json");
        let input_args = vec![
            FIRST_ARG.to_string(),
            file_path.to_str().unwrap().to_string(),
        ];
        let result = parse_detection_rule_json(&input_args);

        assert!(result.is_ok());
        let returned_json = result.unwrap();
        assert!(returned_json.is_object());
    }

    #[test]
    fn parse_request_allow_list_filepath_from_args_valid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.child("file.json");
        input_file.touch().unwrap();

        let input_args = vec![
            FIRST_ARG.to_string(),
            input_file.path().to_str().unwrap().to_string(),
            input_file.path().to_str().unwrap().to_string(),
        ];
        let result = parse_request_allow_list_filepath_from_args(&input_args);

        assert!(result.is_ok());
        let optional_path_buf = result.unwrap().clone();
        assert!(optional_path_buf.is_some());
        let returned_path = optional_path_buf.unwrap();
        assert_eq!(returned_path, input_file.path().canonicalize().unwrap());
    }

    #[test]
    fn parse_request_allow_list_json_rejects_nonexistent_file() {
        let invalid_file_path: &str = "/not_real_dir/not_real_file.json";
        let input_args = vec![
            FIRST_ARG.to_string(),
            invalid_file_path.to_string(),
            invalid_file_path.to_string(),
        ];
        let result = parse_request_allow_list_json(&input_args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            format!("Problem parsing request allow-list filepath: {INVALID_OR_UNSAFE_PATH_MSG}",)
        );
    }

    #[test]
    fn parse_request_allow_list_json_rejects_dir() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap().to_string();
        let input_args = vec![
            FIRST_ARG.to_string(),
            "file1.json".to_string(),
            dir_path.to_string(),
        ];
        let result = parse_request_allow_list_json(&input_args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            format!("Problem parsing request allow-list filepath: {DIR_FILEPATH_MSG}",)
        );
    }

    #[test]
    fn parse_request_allow_list_json_returns_none_if_not_three_args() {
        let empty_args: Vec<String> = Vec::new();
        let too_few_args_vector: Vec<String> =
            vec![FIRST_ARG.to_string(), "file1.json".to_string()];
        let too_many_args_vector = vec![
            FIRST_ARG.to_string(),
            "file1.json".to_string(),
            "file2.json".to_string(),
            "file3.json".to_string(),
        ];
        for args_vector in [empty_args, too_few_args_vector, too_many_args_vector] {
            let result = parse_request_allow_list_json(&args_vector);
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }
    }

    #[test]
    fn parse_request_allow_list_json_valid_file() {
        let detection_rule_filepath =
            Path::new("resources/test/valid_detector_rules/simple_no_op_rule.json");
        let request_allow_list_filepath = Path::new(
            "resources/test/valid_request_allow_lists/simple_cli_request_allow_list.json",
        );
        let input_args = vec![
            FIRST_ARG.to_string(),
            detection_rule_filepath.to_str().unwrap().to_string(),
            request_allow_list_filepath.to_str().unwrap().to_string(),
        ];
        let result = parse_request_allow_list_json(&input_args);

        assert!(result.is_ok());
        let optional_json = result.unwrap().clone();
        assert!(optional_json.is_some());
        assert!(optional_json.unwrap().is_object());
    }
}
