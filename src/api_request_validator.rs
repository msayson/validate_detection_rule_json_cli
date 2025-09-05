use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

#[derive(Deserialize, Serialize)]
struct ApiRequest {
    method: String,
    url: String,
    headers: Option<HashMap<String, String>>,
}

impl fmt::Debug for ApiRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.headers {
            Some(headers) => f
                .debug_struct("ApiRequest")
                .field("method", &self.method)
                .field("url", &self.url)
                .field("headers", &headers)
                .finish(),
            None => f
                .debug_struct("ApiRequest")
                .field("method", &self.method)
                .field("url", &self.url)
                .finish(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct AllowListedValuesForHeader {
    header: String,
    allowed_values: HashSet<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AllowListedApiRequest {
    method: String,
    url: String,
    allowed_values_for_header: Option<Vec<AllowListedValuesForHeader>>,
}

fn parse_api_request(request: &serde_json::Value) -> Result<ApiRequest, String> {
    let api_request: ApiRequest = serde_json::from_value(request.clone()).map_err(|e| {
        format!("Validation error: Failed to parse API request from JSON {request:#?}, error: {e}")
    })?;
    Ok(api_request)
}

fn parse_allow_listed_api_request(
    request: &serde_json::Value,
) -> Result<AllowListedApiRequest, String> {
    let allow_listed_request: AllowListedApiRequest = serde_json::from_value(request.clone()).map_err(|e| {
        format!("Validation error: Failed to parse allow-listed API request from JSON {request:#?}, error: {e}")
    })?;
    Ok(allow_listed_request)
}

fn validate_api_headers_match_allow_list(
    request: &ApiRequest,
    allow_listed_request: &AllowListedApiRequest,
) -> Result<(), String> {
    if request.headers.is_none() || allow_listed_request.allowed_values_for_header.is_none() {
        return Ok(());
    }
    let request_headers = request.headers.as_ref().unwrap();

    let allowed_values_for_headers = allow_listed_request
        .allowed_values_for_header
        .as_ref()
        .unwrap();
    for allowed_values_for_header in allowed_values_for_headers {
        let header: &String = &allowed_values_for_header.header;
        let allowed_values: &HashSet<String> = &allowed_values_for_header.allowed_values;

        if !request_headers.contains_key(header) {
            continue;
        }
        let request_header_value = request_headers.get(header).unwrap();
        if !allowed_values.contains(request_header_value) {
            return Err(format!(
                "Validation error: '{} {}' API requests with header value '{header}: {request_header_value}' is not allowed by the request allow-list, which only allows values: {allowed_values:#?} for this header",
                request.method, request.url
            ));
        }
    }

    Ok(())
}

/// Validates an API request against an allow-list of API requests.
///
/// # Arguments
/// * `request` - A JSON value representing the API request to validate.
/// * `allow_listed_api_requests` - An optional vector of JSON values representing the allow-listed API requests.
///   If none, no API requests are allowed.
///
/// # Returns
/// * `Ok(())` if the API request is allowed by the request allow-list.
/// * `Err(String)` An error message if the API request is not allowed.
///
/// # Errors
/// Returns an error if the API request is not allowed by the request allow-list.
pub fn validate_api_request(
    request: &serde_json::Value,
    allow_listed_api_requests: Option<&Vec<serde_json::Value>>,
) -> Result<(), String> {
    let parsed_request = parse_api_request(request)?;

    if let Some(allow_listed_requests) = allow_listed_api_requests {
        for allow_listed_request in allow_listed_requests {
            let parsed_allow_listed_request = parse_allow_listed_api_request(allow_listed_request)?;
            if parsed_request.method == parsed_allow_listed_request.method
                && parsed_request.url == parsed_allow_listed_request.url
            {
                return validate_api_headers_match_allow_list(
                    &parsed_request,
                    &parsed_allow_listed_request,
                );
            }
        }
        Err(format!(
            "Validation error: API request {parsed_request:#?} is not allowed by the request allow-list",
        ))
    } else {
        Err(format!(
            "Validation error: API request {parsed_request:#?} is not allowed as no API requests are allow-listed"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_API_METHOD: &str = "GET";
    const TEST_API_URL: &str = "https://example.com/api/resource";

    #[test]
    fn test_parse_api_request_valid_request() {
        let valid_api_request_json: serde_json::Value = serde_json::json!({
            "method": TEST_API_METHOD,
            "url": TEST_API_URL,
            "headers": {
                "Authorization": "Bearer token"
            },
            "body": {
                "param1": "value1",
                "param2": "value2"
            }
        });
        let optional_parsed_api_request = parse_api_request(&valid_api_request_json);
        assert!(
            optional_parsed_api_request.is_ok(),
            "Unexpected validation error: {:?}",
            optional_parsed_api_request.err()
        );
        let parsed_api_request = optional_parsed_api_request.unwrap();
        assert_eq!(parsed_api_request.method, TEST_API_METHOD);
        assert_eq!(parsed_api_request.url, TEST_API_URL);
    }

    #[test]
    fn test_parse_api_request_invalid_request_missing_method() {
        let invalid_api_request_json: serde_json::Value = serde_json::json!({
            "url": TEST_API_URL,
            "headers": {
                "Authorization": "Bearer token"
            }
        });
        let optional_parsed_api_request = parse_api_request(&invalid_api_request_json);
        assert!(
            optional_parsed_api_request.is_err(),
            "Expected validation error but got success: {:?}",
            optional_parsed_api_request.ok()
        );
        assert_eq!(
            optional_parsed_api_request.unwrap_err(),
            format!(
                "Validation error: Failed to parse API request from JSON {invalid_api_request_json:#?}, error: missing field `method`"
            )
        );
    }

    #[test]
    fn test_validate_api_request_rejects_if_no_allow_listed_api_requests() {
        let api_request_json: serde_json::Value = serde_json::json!({
            "method": TEST_API_METHOD,
            "url": TEST_API_URL
        });
        let result = validate_api_request(&api_request_json, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            format!(
                "Validation error: API request ApiRequest {{\n    method: \"{TEST_API_METHOD}\",\n    url: \"{TEST_API_URL}\",\n}} is not allowed as no API requests are allow-listed"
            )
        );
    }

    #[test]
    fn test_validate_api_request_rejects_if_not_in_allow_list() {
        let api_request_json: serde_json::Value = serde_json::json!({
            "method": TEST_API_METHOD,
            "url": TEST_API_URL
        });

        let other_url = "https://example.com/api/other_resource";
        let allow_listed_api_requests: Vec<serde_json::Value> = vec![
            serde_json::json!({
                "method": "POST",
                "url": TEST_API_URL
            }),
            serde_json::json!({
                "method": TEST_API_METHOD,
                "url": other_url
            }),
            serde_json::json!({
                "method": "POST",
                "url": other_url
            }),
        ];
        let result = validate_api_request(&api_request_json, Some(&allow_listed_api_requests));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            format!(
                "Validation error: API request ApiRequest {{\n    method: \"{TEST_API_METHOD}\",\n    url: \"{TEST_API_URL}\",\n}} is not allowed by the request allow-list"
            )
        );
    }

    #[test]
    fn test_validate_api_request_accepts_if_in_allow_list() {
        let api_request_json: serde_json::Value = serde_json::json!({
            "method": TEST_API_METHOD,
            "url": TEST_API_URL,
            "headers": {
                "TestHeader": "TestHeaderValue"
            }
        });

        let other_url = "https://example.com/api/other_resource";
        let allow_listed_api_requests: Vec<serde_json::Value> = vec![
            serde_json::json!({
                "method": "POST",
                "url": TEST_API_URL
            }),
            serde_json::json!({
                "method": TEST_API_METHOD,
                "url": other_url
            }),
            serde_json::json!({
                "method": "POST",
                "url": other_url
            }),
            api_request_json.clone(),
        ];
        let result = validate_api_request(&api_request_json, Some(&allow_listed_api_requests));
        assert!(
            result.is_ok(),
            "Unexpected validation error: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_validate_api_request_rejects_if_header_value_not_in_allow_list() {
        let api_request_json: serde_json::Value = serde_json::json!({
            "method": "POST",
            "url": "https://dynamodb.eu-west-2.amazonaws.com",
            "headers": {
                "X-Amz-Target": "DynamoDB_20120810.DescribeContinuousBackups"
            }
        });
        let request_allow_list_json: Vec<serde_json::Value> = vec![serde_json::json!({
            "method": "POST",
            "url": "https://dynamodb.eu-west-2.amazonaws.com",
            "allowed_values_for_header": [
                {
                    "header": "X-Amz-Target",
                    "allowed_values": ["DynamoDB_20120810.ListTables"]
                }
            ]
        })];
        let result = validate_api_request(&api_request_json, Some(&request_allow_list_json));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Validation error: 'POST https://dynamodb.eu-west-2.amazonaws.com' API requests with header value 'X-Amz-Target: DynamoDB_20120810.DescribeContinuousBackups' is not allowed by the request allow-list, which only allows values: {\n    \"DynamoDB_20120810.ListTables\",\n} for this header"
        );
    }

    #[test]
    fn test_validate_api_request_accepts_if_header_value_in_allow_list() {
        let api_request_json: serde_json::Value = serde_json::json!({
            "method": "POST",
            "url": "https://dynamodb.eu-west-2.amazonaws.com",
            "headers": {
                "X-Amz-Target": "DynamoDB_20120810.ListTables",
                "Content-Type": "application/x-amz-json-1.0"
            }
        });
        let request_allow_list_json: Vec<serde_json::Value> = vec![serde_json::json!({
            "method": "POST",
            "url": "https://dynamodb.eu-west-2.amazonaws.com",
            "allowed_values_for_header": [
                {
                    "header": "X-Amz-Target",
                    "allowed_values": ["DynamoDB_20120810.ListTables"]
                }
            ]
        })];
        let result = validate_api_request(&api_request_json, Some(&request_allow_list_json));
        assert!(
            result.is_ok(),
            "Unexpected validation error: {:?}",
            result.err()
        );
    }
}
