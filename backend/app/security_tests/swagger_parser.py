"""
Parses OpenAPI/Swagger JSON specs and extracts all endpoints,
HTTP methods, parameters (path, query, body), and schemas.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EndpointParam:
    name: str
    location: str  # path, query, header, cookie, body
    schema_type: str
    required: bool
    example: Any = None


@dataclass
class Endpoint:
    path: str
    method: str
    operation_id: str
    params: list[EndpointParam] = field(default_factory=list)
    body_schema: dict = field(default_factory=dict)
    requires_auth: bool = False
    tags: list[str] = field(default_factory=list)


def parse_swagger(spec: dict) -> list[Endpoint]:
    """Extract all endpoints from OpenAPI 2.x / 3.x spec."""
    endpoints: list[Endpoint] = []
    paths = spec.get("paths", {})
    global_security = bool(spec.get("security", []))

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
            operation = path_item.get(method)
            if not operation:
                continue

            endpoint = Endpoint(
                path=path,
                method=method.upper(),
                operation_id=operation.get("operationId", f"{method}_{path}"),
                tags=operation.get("tags", []),
                requires_auth=global_security or bool(operation.get("security", [])),
            )

            # Extract parameters (path, query, header, cookie)
            all_params = list(path_item.get("parameters", []))
            all_params += operation.get("parameters", [])
            for param in all_params:
                if not isinstance(param, dict):
                    continue
                schema = param.get("schema", {}) or {}
                endpoint.params.append(EndpointParam(
                    name=param.get("name", ""),
                    location=param.get("in", "query"),
                    schema_type=schema.get("type", "string"),
                    required=param.get("required", False),
                    example=schema.get("example") or param.get("example"),
                ))

            # Extract request body (OpenAPI 3.x)
            req_body = operation.get("requestBody", {})
            if req_body:
                content = req_body.get("content", {})
                for content_type, content_schema in content.items():
                    if "schema" in content_schema:
                        endpoint.body_schema = {
                            "content_type": content_type,
                            "schema": content_schema["schema"],
                        }
                        # Also extract body properties as params
                        props = content_schema["schema"].get("properties", {})
                        for prop_name, prop_schema in props.items():
                            endpoint.params.append(EndpointParam(
                                name=prop_name,
                                location="body",
                                schema_type=prop_schema.get("type", "string"),
                                required=prop_name in content_schema["schema"].get("required", []),
                                example=prop_schema.get("example"),
                            ))
                        break

            # OpenAPI 2.x body params
            for param in all_params:
                if isinstance(param, dict) and param.get("in") == "body":
                    schema = param.get("schema", {})
                    endpoint.body_schema = {"content_type": "application/json", "schema": schema}
                    props = schema.get("properties", {})
                    for prop_name, prop_schema in props.items():
                        endpoint.params.append(EndpointParam(
                            name=prop_name,
                            location="body",
                            schema_type=prop_schema.get("type", "string"),
                            required=prop_name in schema.get("required", []),
                        ))

            endpoints.append(endpoint)

    return endpoints


def build_test_url(base_url: str, path: str, path_params: dict) -> str:
    """Replace {param} placeholders in path with actual values."""
    url_path = path
    for k, v in path_params.items():
        url_path = url_path.replace(f"{{{k}}}", str(v))
    base_url = base_url.rstrip("/")
    return f"{base_url}{url_path}"


def get_safe_body(endpoint: Endpoint) -> dict:
    """Generate a minimal safe request body from schema."""
    schema = endpoint.body_schema.get("schema", {})
    props = schema.get("properties", {})
    body = {}
    for name, prop in props.items():
        ptype = prop.get("type", "string")
        if ptype == "string":
            body[name] = prop.get("example", "test_value")
        elif ptype == "integer":
            body[name] = prop.get("example", 1)
        elif ptype == "boolean":
            body[name] = True
        elif ptype == "array":
            body[name] = []
        elif ptype == "object":
            body[name] = {}
    return body