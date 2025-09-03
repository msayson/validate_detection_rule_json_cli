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

### License

This project is licensed under the [GNU General Public License, version 3](LICENSE).