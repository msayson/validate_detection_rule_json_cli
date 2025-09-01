# validate_detection_rule_json_cli

[![Cargo Test](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/test.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/test.yaml) [![Lint](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/lint.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/lint.yaml) [![Audit](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/audit.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/audit.yaml) [![Semgrep](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/semgrep.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/semgrep.yaml)

Rust-based CLI to validate whether a file at a given filepath matches the [detection rule JSON Schema](resources/detection_rule_schema.json).

Usage:
* `validate_json FILEPATH` - validate provided file against the detection rule JSON Schema
* `validate_json --help` - display help message and exit
