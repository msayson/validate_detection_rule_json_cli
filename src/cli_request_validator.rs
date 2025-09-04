fn parse_cli_command(cli_request: &serde_json::Value) -> Result<String, String> {
    let command_value = cli_request
        .get("command")
        .ok_or_else(|| "CLI request command not found".to_string())?;
    let cli_command: &str = command_value
        .as_str()
        .ok_or_else(|| "CLI request command {command_value:?} is not a string".to_string())?;
    Ok(cli_command.to_string())
}

fn validate_no_required_args(
    cli_command: &str,
    allow_listed_requests_for_cli_command: Vec<&serde_json::Value>,
) -> Result<(), String> {
    let mut allow_list_includes_requests_requiring_args = false;

    for allowed_cli_request in allow_listed_requests_for_cli_command {
        let exact_args = allowed_cli_request.get("exactArgs");
        let initial_args = allowed_cli_request.get("initialArgs");

        // Explicitly allow-listing the command without args
        if exact_args.is_none() && initial_args.is_none() {
            return Ok(());
        }

        if exact_args.is_some() || initial_args.is_some() {
            allow_list_includes_requests_requiring_args = true;
        }
    }

    if allow_list_includes_requests_requiring_args {
        Err(format!(
            "Validation error: CLI command '{cli_command}' without arguments is not allowed by the request allow-list"
        ))?;
    }
    Ok(())
}

fn validate_cli_args_match_allow_list(
    cli_command: &str,
    cli_request: &serde_json::Value,
    allow_listed_requests_for_cli_command: Vec<&serde_json::Value>,
) -> Result<(), String> {
    let optional_cli_args = cli_request.get("args");
    if optional_cli_args.is_none() {
        return validate_no_required_args(cli_command, allow_listed_requests_for_cli_command);
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

/// Validates a CLI request against an allow-list of CLI requests.
///
/// # Arguments
/// * `cli_request` - A JSON value representing the CLI request to validate.
/// * `allow_listed_cli_requests` - An optional vector of JSON values representing the allow-listed CLI requests.
///   If none, no CLI requests are allowed.
///
/// # Returns
/// * `Ok(())` if the CLI request is allowed by the request allow-list.
/// * `Err(String)` An error message if the CLI request is not allowed.
///
/// # Errors
/// Returns an error if the CLI command is not allowed by the request allow-list.
pub fn validate_cli_request(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_cli_request_passes_exact_allowed_cli_command_args() {
        let cli_request = serde_json::json!({
            "command": "echo",
            "args": [
                "Hello",
                "world!"
            ]
        });
        let allow_listed_cli_requests = Some(&Vec::from([serde_json::json!({
            "command": "echo",
            "exactArgs": [
                "Hello",
                "world!"
            ]
        })]));

        let result = validate_cli_request(&cli_request, allow_listed_cli_requests);
        assert!(
            result.is_ok(),
            "Unexpected validation error: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn validate_cli_request_rejects_mismatch_to_required_exact_args() {
        let allow_listed_cli_requests = Some(&Vec::from([serde_json::json!({
            "command": "echo",
            "exactArgs": [
                "Hello",
                "world!"
            ]
        })]));

        for cli_request in [
            serde_json::json!({
                "command": "echo",
                "args": [
                    "Hello"
                ]
            }),
            serde_json::json!({
                "command": "echo",
                "args": [
                    "Hello",
                    "world!",
                    "My name is HAL."
                ]
            }),
            serde_json::json!({
                "command": "echo",
                "args": [
                    "Goodbye"
                ]
            }),
            serde_json::json!({
                "command": "echo",
                "args": []
            }),
            serde_json::json!({
                "command": "echo"
            }),
        ] {
            let result = validate_cli_request(&cli_request, allow_listed_cli_requests);
            assert!(
                result.is_err(),
                "Unexpected validation result for CLI request {cli_request:?}: {result:?}"
            );
            let error_message = result.unwrap_err();
            assert!(
                error_message.contains("is not allowed by the request allow-list"),
                "Unexpected validation result: {error_message:?}"
            );
        }
    }

    #[test]
    fn validate_cli_request_passes_matching_allowed_cli_command_args() {
        let allow_listed_cli_requests = Some(&Vec::from([serde_json::json!({
            "command": "echo",
            "initialArgs": [
                "Hello",
                "world!"
            ]
        })]));

        for cli_request in [
            serde_json::json!({
                "command": "echo",
                "args": [
                    "Hello",
                    "world!"
                ]
            }),
            serde_json::json!({
                "command": "echo",
                "args": [
                    "Hello",
                    "world!",
                    "My name is HAL."
                ]
            }),
        ] {
            let result = validate_cli_request(&cli_request, allow_listed_cli_requests);
            assert!(
                result.is_ok(),
                "Unexpected validation error: {:?}",
                result.unwrap_err()
            );
        }
    }

    #[test]
    fn validate_cli_request_rejects_missing_required_initial_args() {
        let allow_listed_cli_requests = Some(&Vec::from([serde_json::json!({
            "command": "echo",
            "initialArgs": [
                "Hello",
                "world!"
            ]
        })]));

        for cli_request in [
            serde_json::json!({
                "command": "echo",
                "args": [
                    "Hello"
                ]
            }),
            serde_json::json!({
                "command": "echo",
                "args": [
                    "Goodbye"
                ]
            }),
            serde_json::json!({
                "command": "echo",
                "args": []
            }),
            serde_json::json!({
                "command": "echo"
            }),
        ] {
            let result = validate_cli_request(&cli_request, allow_listed_cli_requests);
            assert!(
                result.is_err(),
                "Unexpected validation result for CLI request {cli_request:?}: {result:?}"
            );
            let error_message = result.unwrap_err();
            assert!(
                error_message.contains("is not allowed by the request allow-list"),
                "Unexpected validation result: {error_message:?}"
            );
        }
    }

    #[test]
    fn validate_cli_request_allows_no_args_if_allow_listed() {
        let cli_request = serde_json::json!({
            "command": "echo"
        });
        let allow_listed_cli_requests = Some(&Vec::from([
            serde_json::json!({
                "command": "echo",
                "initialArgs": [
                    "Hello",
                    "world!"
                ]
            }),
            serde_json::json!({
                "command": "echo"
            }),
        ]));

        let result = validate_cli_request(&cli_request, allow_listed_cli_requests);
        assert!(
            result.is_ok(),
            "Unexpected validation error: {:?}",
            result.unwrap_err()
        );
    }
}
