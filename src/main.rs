use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const UNEXPECTED_ARGS_MSG: &str = "Received invalid arguments\n  'validate_json --help' for more information.";
const INVALID_OR_UNSAFE_PATH_MSG: &str = "Invalid or unsafe path";
const DIR_FILEPATH_MSG: &str = "Must provide a file, not a directory";

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

fn parse_filepath_from_args(args: &[String]) -> Result<PathBuf, &'static str> {
    // Validate provides required arguments
    if 2 != args.len() {
        return Err(UNEXPECTED_ARGS_MSG);
    }
    let first_input = &args[1];
    if first_input == "--help" {
        print_help_and_exit();
    }

    // Validate input filepath
    let canonical_filepath = match fs::canonicalize(first_input) {
        Ok(path) => path,
        Err(_) => return Err(INVALID_OR_UNSAFE_PATH_MSG)
    };
    if canonical_filepath.is_dir() {
        return Err(DIR_FILEPATH_MSG);
    }
    Ok(canonical_filepath)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let path_buf: PathBuf = parse_filepath_from_args(&args).unwrap_or_else(|err| {
        eprintln!("Problem parsing filepath: {err}");
        std::process::exit(1);
    });
    let path: &Path = path_buf.as_path();
    println!("Validating file at path {}", path.display());
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
}

