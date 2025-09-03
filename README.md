# validate_detection_rule_json_cli

[![Cargo Test](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/test.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/test.yaml) [![Lint](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/lint.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/lint.yaml) [![Audit](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/audit.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/audit.yaml) [![Semgrep](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/semgrep.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/semgrep.yaml)

Rust-based CLI to validate whether a detection rule JSON definition matches the [detection rule JSON Schema](resources/detection_rule_schema.json), and matches a request allow-list if provided by the user.

Usage:
* `validate_detection_rule_json DETECTION_RULE_FILEPATH` - validate provided file against the detection rule JSON Schema
* `validate_detection_rule_json DETECTION_RULE_FILEPATH REQUEST_ALLOW_LIST_FILEPATH` - validate detection rule and request allow-list against the detection rule and request allow-list JSON Schemas, and validate that the detection rule satisfies the constraints of the request allow-list
* `validate_detection_rule_json --help` - display help message and exit
