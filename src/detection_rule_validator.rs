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

fn parse_cli_command(cli_request: &serde_json::Value) -> Result<String, String> {
    let command_value = cli_request
        .get("command")
        .ok_or_else(|| "CLI request command not found".to_string())?;
    let cli_command: &str = command_value
        .as_str()
        .ok_or_else(|| "CLI request command {command_value:?} is not a string".to_string())?;
    Ok(cli_command.to_string())
}

fn validate_cli_args_match_allow_list(
    cli_command: &str,
    cli_request: &serde_json::Value,
    allow_listed_requests_for_cli_command: Vec<&serde_json::Value>,
) -> Result<(), String> {
    let optional_cli_args = cli_request.get("args");
    if optional_cli_args.is_none() {
        return Ok(());
    }
    let cli_args = optional_cli_args.unwrap().as_array().unwrap();

    for allowed_cli_request in allow_listed_requests_for_cli_command {
        let exact_args = allowed_cli_request.get("exactArgs");
        let initial_args = allowed_cli_request.get("initialArgs");

        match (exact_args, initial_args) {
            (Some(exact_args), _) => {
                let exact_args_array = exact_args.as_array().unwrap();
                if exact_args_array == cli_args {
                    return Ok(());
                }
            }
            (None, Some(initial_args)) => {
                let initial_args_array = initial_args.as_array().unwrap();
                if cli_args.starts_with(initial_args_array) {
                    return Ok(());
                }
            }
            (None, None) => {
                // If neither exactArgs nor initialArgs is specified, any args are allowed
                return Ok(());
            }
        }
    }

    Err(format!(
        "Validation error: CLI command '{cli_command}' with arguments '{cli_args:#?}' is not allowed by the request allow-list"
    ))
}

fn validate_cli_request_matches_allow_list(
    cli_request: &serde_json::Value,
    allow_listed_cli_requests: Option<&Vec<serde_json::Value>>,
) -> Result<(), String> {
    let cli_command = parse_cli_command(cli_request)?;

    if allow_listed_cli_requests.is_none() {
        return Err(format!(
            "Validation error: CLI command '{cli_command}' is not allowed, no allow-listed CLI commands"
        ));
    }
    let allow_listed_cli_requests_matching_cli_command = allow_listed_cli_requests
        .unwrap()
        .iter()
        .filter(|allowed_cli_request| {
            allowed_cli_request
                .get("command")
                .unwrap()
                .as_str()
                .unwrap()
                == cli_command
        })
        .collect::<Vec<&serde_json::Value>>();

    if allow_listed_cli_requests_matching_cli_command.is_empty() {
        return Err(format!(
            "Validation error: CLI command '{cli_command}' is not allowed, allow-listed CLI commands: {:?}",
            allow_listed_cli_requests
                .unwrap()
                .iter()
                .map(|request| request.get("command").unwrap().as_str().unwrap())
                .collect::<Vec<&str>>()
        ));
    }

    validate_cli_args_match_allow_list(
        &cli_command,
        cli_request,
        allow_listed_cli_requests_matching_cli_command,
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
        if step_request_type == "cli" {
            validate_cli_request_matches_allow_list(request, allow_listed_cli_requests)?;
        }
        // TODO: validate API request against allow-list
    }
    Ok(())
}

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
            "resources/test/valid_detector_rules/simple_no_op_rule.json",
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
            "resources/test/valid_detector_rules/simple_no_op_rule.json",
            "detection rule",
        )
        .unwrap();
        let request_allow_list_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/valid_request_allow_lists/simple_cli_request_allow_list.json",
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
    fn validate_detection_rule_data_passes_exact_allowed_cli_command_args() {
        let detection_rule_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/valid_detector_rules/exact_allowed_cli_args_rule.json",
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
        assert!(
            result.is_ok(),
            "Unexpected validation error: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn validate_detection_rule_data_rejects_non_exact_cli_command_args() {
        let detection_rule_json: serde_json::Value = parse_json_from_filepath(
            "resources/test/valid_detector_rules/extra_cli_args_rule.json",
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
            "Validation error: CLI command 'echo' with arguments '[\n    String(\"Hello\"),\n    String(\"world!\"),\n    String(\"My name is HAL.\"),\n]' is not allowed by the request allow-list"
        );
    }

    #[test]
    fn validate_detection_rule_data_passes_initial_allowed_cli_command_args() {
        for input_file_path in [
            "resources/test/valid_detector_rules/exact_allowed_cli_args_rule.json",
            "resources/test/valid_detector_rules/extra_cli_args_rule.json",
        ] {
            let detection_rule_json: serde_json::Value =
                parse_json_from_filepath(input_file_path, "detection rule").unwrap();
            let request_allow_list_json: serde_json::Value = parse_json_from_filepath(
                "resources/test/valid_request_allow_lists/initial_cli_args_allow_list.json",
                "request allow-list",
            )
            .unwrap();

            let result =
                validate_detection_rule_data(&detection_rule_json, Some(&request_allow_list_json));
            assert!(
                result.is_ok(),
                "Unexpected validation error for input file '{input_file_path}': {:?}",
                result.unwrap_err()
            );
        }
    }

    #[test]
    fn validate_detection_rule_data_rejects_missing_initial_allowed_cli_command_args() {
        for input_file_path in [
            "resources/test/valid_detector_rules/simple_no_op_rule.json",
            "resources/test/valid_detector_rules/missing_initial_cli_args_rule.json",
        ] {
            let detection_rule_json: serde_json::Value =
                parse_json_from_filepath(input_file_path, "detection rule").unwrap();
            let request_allow_list_json: serde_json::Value = parse_json_from_filepath(
                "resources/test/valid_request_allow_lists/initial_cli_args_allow_list.json",
                "request allow-list",
            )
            .unwrap();

            let result =
                validate_detection_rule_data(&detection_rule_json, Some(&request_allow_list_json));
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .starts_with("Validation error: CLI command 'echo' with arguments")
            );
        }
    }
}
