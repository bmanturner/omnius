use serde_json::{Value, json};

fn problem_response(description: &'static str) -> Value {
    json!({
        "description": description,
        "headers": {
            "Cache-Control": {
                "description": "Prevents storage of error details.",
                "schema": {"type": "string", "const": "no-store"}
            }
        },
        "content": {
            "application/problem+json": {
                "schema": {"$ref": "#/components/schemas/ProblemDetails"}
            }
        }
    })
}

fn typed_problem_response(description: &'static str, schema: &'static str) -> Value {
    let mut response = problem_response(description);
    response["content"]["application/problem+json"]["schema"] = json!({"$ref": schema});
    response
}

fn bin_id_parameter() -> Value {
    json!({
        "name": "bin_id",
        "in": "path",
        "required": true,
        "description": "UUIDv7 request-bin identifier.",
        "schema": {"type": "string", "format": "uuid"}
    })
}

fn capture_operation(operation_id: &'static str, summary: &'static str, head: bool) -> Value {
    let accepted = if head {
        json!({"description": "Request accepted and captured; HEAD has an empty response body."})
    } else {
        json!({
            "description": "Request accepted and captured.",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/CaptureAccepted"}
                }
            }
        })
    };
    json!({
        "operationId": operation_id,
        "tags": ["captures"],
        "summary": summary,
        "security": [],
        "parameters": [bin_id_parameter()],
        "requestBody": {
            "required": false,
            "description": "Opaque request bytes retained as base64, limited to 16384 raw bytes. The aggregate raw request-header name and value bytes are independently limited to 16384 bytes.",
            "content": {
                "application/octet-stream": {
                    "schema": {
                        "type": "string",
                        "format": "binary",
                        "maxLength": 16384
                    }
                }
            }
        },
        "responses": {
            "202": accepted,
            "404": problem_response("The request bin is absent or expired."),
            "405": problem_response("The HTTP method cannot be captured."),
            "413": typed_problem_response(
                "The capture body exceeds 16384 bytes (CAPTURE_BODY_TOO_LARGE) or aggregate raw header names and values exceed 16384 bytes (CAPTURE_HEADERS_TOO_LARGE); no capture is stored.",
                "#/components/schemas/CaptureLimitProblemDetails",
            ),
            "500": problem_response("The request could not be captured.")
        }
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the complete application-owned OpenAPI document is intentionally kept in one value"
)]
pub(super) fn document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Request Bin",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "A process-local request bin with bearer-protected inspection, at most 64 live bins, and the newest 25 captures retained per bin."
        },
        "tags": [
            {
                "name": "request-bins",
                "description": "Create, inspect, and delete request bins."
            },
            {
                "name": "captures",
                "description": "Submit requests for bounded in-memory capture."
            }
        ],
        "paths": {
            "/bins": {
                "post": {
                    "operationId": "createRequestBin",
                    "tags": ["request-bins"],
                    "summary": "Create a request bin",
                    "security": [],
                    "requestBody": {
                        "required": false,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateRequestBinRequest"}
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Request bin created. The read token is returned only once.",
                            "headers": {
                                "Cache-Control": {
                                    "description": "Prevents storage of the one-time read token.",
                                    "schema": {"type": "string", "const": "no-store"}
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/CreateRequestBinResponse"}
                                }
                            }
                        },
                        "400": problem_response("The JSON request body is malformed."),
                        "422": problem_response("ttl_seconds is outside the accepted range."),
                        "503": typed_problem_response(
                            "All 64 live request-bin slots are occupied after expired bins are purged (BIN_CAPACITY_EXCEEDED); no live bin is evicted.",
                            "#/components/schemas/BinCapacityProblemDetails",
                        ),
                        "500": problem_response("The request bin could not be created.")
                    }
                }
            },
            "/bins/{bin_id}": {
                "get": {
                    "operationId": "inspectRequestBin",
                    "tags": ["request-bins"],
                    "summary": "Inspect a request bin",
                    "security": [{"binReadToken": []}],
                    "parameters": [bin_id_parameter()],
                    "responses": {
                        "200": {
                            "description": "Request-bin metadata and up to 25 retained captures ordered oldest to newest.",
                            "headers": {
                                "Cache-Control": {
                                    "description": "Prevents storage of captured request data.",
                                    "schema": {"type": "string", "const": "no-store"}
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/InspectRequestBinResponse"}
                                }
                            }
                        },
                        "404": problem_response("The request bin is absent, expired, or the read token is invalid."),
                        "500": problem_response("The request bin could not be inspected.")
                    }
                },
                "delete": {
                    "operationId": "deleteRequestBin",
                    "tags": ["request-bins"],
                    "summary": "Delete a request bin",
                    "security": [{"binReadToken": []}],
                    "parameters": [bin_id_parameter()],
                    "responses": {
                        "204": {"description": "Request bin deleted."},
                        "404": problem_response("The request bin is absent, expired, or the read token is invalid."),
                        "500": problem_response("The request bin could not be deleted.")
                    }
                }
            },
            "/capture/{bin_id}": {
                "get": capture_operation("captureRequestGet", "Capture a GET request", false),
                "head": capture_operation("captureRequestHead", "Capture a HEAD request", true),
                "post": capture_operation("captureRequestPost", "Capture a POST request", false),
                "put": capture_operation("captureRequestPut", "Capture a PUT request", false),
                "patch": capture_operation("captureRequestPatch", "Capture a PATCH request", false),
                "delete": capture_operation("captureRequestDelete", "Capture a DELETE request", false),
                "options": capture_operation("captureRequestOptions", "Capture an OPTIONS request", false),
                "trace": capture_operation("captureRequestTrace", "Capture a TRACE request", false)
            }
        },
        "components": {
            "securitySchemes": {
                "binReadToken": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "opaque",
                    "description": "Read token returned exactly once when the bin is created."
                }
            },
            "schemas": {
                "CreateRequestBinRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "ttl_seconds": {
                            "type": "integer",
                            "format": "uint64",
                            "minimum": 60,
                            "maximum": 86400,
                            "default": 3600
                        }
                    }
                },
                "CreateRequestBinResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "bin_id",
                        "read_token",
                        "capture_path",
                        "inspect_path",
                        "created_at",
                        "expires_at"
                    ],
                    "properties": {
                        "bin_id": {"type": "string", "format": "uuid"},
                        "read_token": {
                            "type": "string",
                            "description": "A 32-byte base64url token returned only in this response."
                        },
                        "capture_path": {"type": "string", "pattern": "^/capture/"},
                        "inspect_path": {"type": "string", "pattern": "^/bins/"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "expires_at": {"type": "string", "format": "date-time"}
                    }
                },
                "InspectRequestBinResponse": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "bin_id",
                        "capture_path",
                        "inspect_path",
                        "created_at",
                        "expires_at",
                        "captures"
                    ],
                    "properties": {
                        "bin_id": {"type": "string", "format": "uuid"},
                        "capture_path": {"type": "string", "pattern": "^/capture/"},
                        "inspect_path": {"type": "string", "pattern": "^/bins/"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "expires_at": {"type": "string", "format": "date-time"},
                        "captures": {
                            "type": "array",
                            "description": "At most the newest 25 captures, ordered oldest to newest.",
                            "maxItems": 25,
                            "items": {"$ref": "#/components/schemas/Capture"}
                        }
                    }
                },
                "Capture": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "capture_id",
                        "method",
                        "path",
                        "query",
                        "captured_at",
                        "headers",
                        "body_base64"
                    ],
                    "properties": {
                        "capture_id": {"type": "string", "format": "uuid"},
                        "method": {"type": "string"},
                        "path": {"type": "string"},
                        "query": {"type": ["string", "null"]},
                        "captured_at": {"type": "string", "format": "date-time"},
                        "headers": {
                            "type": "object",
                            "description": "Captured headers after enforcing a 16384-byte aggregate limit over every raw header name and value. Sensitive values are stored as [REDACTED].",
                            "additionalProperties": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        },
                        "body_base64": {
                            "type": "string",
                            "description": "Base64 encoding of at most 16384 raw request-body bytes.",
                            "contentEncoding": "base64",
                            "maxLength": 21848
                        }
                    }
                },
                "CaptureAccepted": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["capture_id", "captured_at"],
                    "properties": {
                        "capture_id": {"type": "string", "format": "uuid"},
                        "captured_at": {"type": "string", "format": "date-time"}
                    }
                },
                "BinCapacityProblemDetails": {
                    "allOf": [
                        {"$ref": "#/components/schemas/ProblemDetails"},
                        {
                            "type": "object",
                            "properties": {
                                "status": {"const": 503},
                                "code": {"const": "BIN_CAPACITY_EXCEEDED"}
                            }
                        }
                    ]
                },
                "CaptureLimitProblemDetails": {
                    "allOf": [
                        {"$ref": "#/components/schemas/ProblemDetails"},
                        {
                            "type": "object",
                            "properties": {
                                "status": {"const": 413},
                                "code": {
                                    "enum": [
                                        "CAPTURE_BODY_TOO_LARGE",
                                        "CAPTURE_HEADERS_TOO_LARGE"
                                    ]
                                }
                            }
                        }
                    ]
                },
                "ProblemDetails": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "title", "status", "code", "request_id"],
                    "properties": {
                        "type": {"type": "string", "format": "uri"},
                        "title": {"type": "string"},
                        "status": {"type": "integer", "minimum": 400, "maximum": 599},
                        "code": {
                            "type": "string",
                            "pattern": "^[A-Z][A-Z0-9_]*$"
                        },
                        "request_id": {"type": "string", "format": "uuid"},
                        "detail": {"type": "string"},
                        "errors": {
                            "type": "array",
                            "maxItems": 100,
                            "items": {"$ref": "#/components/schemas/ProblemFieldError"}
                        }
                    }
                },
                "ProblemFieldError": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["pointer", "code", "message"],
                    "properties": {
                        "pointer": {"type": "string"},
                        "code": {"type": "string"},
                        "message": {"type": "string"}
                    }
                }
            }
        }
    })
}
