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

    let detection_rule_contents =
        fs::read_to_string(path).map_err(|err| format!("Error reading {file_type} file: {err}"))?;
    let detection_rule_json: serde_json::Value = serde_json::from_str(&detection_rule_contents)
        .map_err(|err| format!("Error parsing {file_type} file as JSON: {err}"))?;
    Ok(detection_rule_json)
}
