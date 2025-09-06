use std::fs;
use std::path::{Path, PathBuf};

pub const INVALID_OR_UNSAFE_PATH_MSG: &str = "Invalid or unsafe path";
pub const DIR_FILEPATH_MSG: &str = "Must provide a file, not a directory";

/// Parses and validates a file path.
///
/// Validates the file path points to a file, not a directory,
/// and returns the canonicalized file path.
///
/// # Arguments
/// * `input_filepath` - A string representing the file path to validate
///
/// # Returns
/// * `Ok(PathBuf)` - A canonicalized, validated file path; OR
/// * `Err(&'static str)` - An error message describing the failure
///
/// # Errors
/// Returns an error if:
/// - The path is invalid or unsafe
/// - The path points to a directory
pub fn parse_filepath(input_filepath: &str) -> Result<PathBuf, &'static str> {
    // Validate a file exists at given filepath
    let Ok(canonical_filepath) = fs::canonicalize(input_filepath) else {
        return Err(INVALID_OR_UNSAFE_PATH_MSG);
    };
    // Validate not a directory
    if canonical_filepath.is_dir() {
        return Err(DIR_FILEPATH_MSG);
    }
    // Return the canonical filepath
    Ok(canonical_filepath)
}

pub fn parse_json_file(path: &Path, file_type: &str) -> Result<serde_json::Value, String> {
    println!("Parsing {file_type} file at path {}", path.display());

    let file_contents =
        fs::read_to_string(path).map_err(|err| format!("Error reading {file_type} file: {err}"))?;
    let contents_json: serde_json::Value = serde_json::from_str(&file_contents)
        .map_err(|err| format!("Error parsing {file_type} file as JSON: {err}"))?;
    Ok(contents_json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_filepath_passes_valid_filepath() {
        let filepath = "resources/test/valid_detector_rules/multiple_request_types_rule.json";
        let result = parse_filepath(filepath);
        assert!(
            result.is_ok(),
            "Expected Ok, got Err: {}",
            result.unwrap_err()
        );
    }

    #[test]
    fn parse_filepath_rejects_directory() {
        let filepath = "resources/test/valid_detector_rules/";
        let result = parse_filepath(filepath);
        assert!(result.is_err());

        let error_msg = result.unwrap_err();
        assert_eq!(error_msg, DIR_FILEPATH_MSG);
    }

    #[test]
    fn parse_filepath_rejects_invalid_path() {
        let filepath = "/not_real_dir/not_real_file.json";
        let result = parse_filepath(filepath);
        assert!(result.is_err());

        let error_msg = result.unwrap_err();
        assert_eq!(error_msg, INVALID_OR_UNSAFE_PATH_MSG);
    }

    #[test]
    fn parse_json_file_passes_valid_json() {
        let filepath = "resources/test/valid_detector_rules/multiple_request_types_rule.json";
        let parsed_filepath = parse_filepath(filepath).unwrap();
        let parsed_json_contents = parse_json_file(&parsed_filepath, "detection rule");
        assert!(
            parsed_json_contents.is_ok(),
            "Expected Ok, got Err: {}",
            parsed_json_contents.unwrap_err()
        );
    }

    #[test]
    fn parse_json_file_rejects_non_json() {
        let filepath = "Cargo.toml";
        let parsed_filepath = parse_filepath(filepath).unwrap();
        let parsed_json_contents = parse_json_file(&parsed_filepath, "detection rule");
        assert!(parsed_json_contents.is_err());
        assert!(
            parsed_json_contents
                .unwrap_err()
                .contains("Error parsing detection rule file as JSON")
        );
    }
}
