# validate_detection_rule_json_cli

[![Cargo Test](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/test.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/test.yaml) [![Lint](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/lint.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/lint.yaml) [![Audit](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/audit.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/audit.yaml) [![Semgrep](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/semgrep.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/semgrep.yaml)

A Rust-based command-line interface (CLI) for validating detection rule JSON definitions against a pre-defined schema and optional request allow-list.

### Overview

This CLI tool validates whether a detection rule JSON definition conforms to the [detection rule JSON Schema](resources/detection_rule_schema.json) and adheres to the constraints defined in a user-provided request allow-list.  It provides a simple and efficient way to validate detection rule schemas prior to executing any detection rule logic.

### Features

* Validates detection rule JSON definitions against a [detection rule JSON Schema](resources/detection_rule_schema.json)
* Validates request allow-list JSON definitions against a [request allow-list JSON Schema](resources/request_allow_list_schema.json) if provided
* Validates detection rules against a request allow-list if one is provided
* Supports validation of CLI commands and API requests
* Provides detailed error messages to help identify and fix validation issues

### Usage

* `validate_detection_rule_json DETECTION_RULE_FILEPATH` - validate provided file against the detection rule JSON Schema
* `validate_detection_rule_json DETECTION_RULE_FILEPATH REQUEST_ALLOW_LIST_FILEPATH` - validate detection rule and request allow-list against the detection rule and request allow-list JSON Schemas, and validate that the detection rule satisfies the constraints of the request allow-list
* `validate_detection_rule_json --help` - display help message and exit

#### Example: Validating a detection rule without a request allow-list

Given the following detection rule at `./resources/test_detection_rule.json`:

```json
{
    "id": "Namespace::TestDetectionRule",
    "name": "Test Rule",
    "description": "This is a test detection rule.",
    "version": "0.1.2",
    "steps": [
        {
            "id": "Test step 1",
            "description": "This is a no-op step.",
            "requestType": "cli",
            "request": {
                "command": "echo",
                "args": [
                    "Hello world!"
                ]
            }
        }
    ]
}
```

`validate_detection_rule_json ./resources/test_detection_rule.json ./resources/test_request_allow_list.json` will succeed and print the message:

```
Validation successful.
```

#### Example: Validating a detection rule with a request allow-list that does not explicitly allow one of the rule's requests

Given the following detection rule at `./resources/test_detection_rule.json`:

```json
{
    "id": "Namespace::TestDetectionRule",
    "name": "Test Rule",
    "description": "This is a test detection rule.",
    "version": "0.1.2",
    "steps": [
        {
            "id": "Test step 1",
            "description": "This is a no-op step.",
            "requestType": "cli",
            "request": {
                "command": "echo",
                "args": [
                    "Hello",
                    "world!"
                ]
            }
        },
        {
            "id": "Test step 2",
            "description": "List files in current directory.",
            "requestType": "cli",
            "request": {
                "command": "ls"
            }
        }
    ]
}
```

and the following request allow-list at `./resources/test_request_allow_list.json`:

```json
{
    "id": "Namespace::TestRequestAllowList",
    "description": "Test request allow-list.",
    "allowedCliCommands": [
        {
            "command": "echo",
            "exactArgs": [
                "Hello",
                "world!"
            ]
        }
    ]
}
```

`validate_detection_rule_json ./resources/test_detection_rule.json ./resources/test_request_allow_list.json` will exit with error code 1 and the following error message:

```
Failed detection rule validations, error: Validation error: CLI command 'ls' is not allowed, allow-listed CLI commands: ["echo"]
```

#### Example: Validating a detection rule that does not match the [detection rule JSON Schema](resources/detection_rule_schema.json)

Given the following detection rule at `./resources/test_detection_rule.json`:

```json
{
    "id": "Namespace::TestDetectionRule",
    "name": "Test Rule",
    "description": "This is a test detection rule.",
    "version": "0.1",
    "steps": [
        {
            "id": "Test step 1",
            "description": "This is a no-op step.",
            "requestType": "cli",
            "request": {
                "command": "echo",
                "args": [
                    "No operation performed."
                ]
            }
        }
    ],
    "unsupported_property": "Test value"
}
```

which has an `unsupported_property` attribute that does not match the required JSON Schema, `validate_detection_rule_json ./resources/test_detection_rule.json` will exit with error code 1 and the following error log:

```
----
Error: Additional properties are not allowed ('unsupported_property' was unexpected)
Instance path:
Schema path: /additionalProperties
Keyword kind: AdditionalProperties { unexpected: ["unsupported_property"] }
----
Failed detection rule validations, error: Validation error for detection rule: Additional properties are not allowed ('unsupported_property' was unexpected)
```

### License

This project is licensed under the [GNU General Public License, version 3](LICENSE).