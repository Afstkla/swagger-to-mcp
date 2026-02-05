"""Generate MCP tool definitions from parsed OpenAPI endpoints."""

from typing import Any


def openapi_type_to_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Convert OpenAPI schema to JSON Schema for MCP tool input."""
    if not schema:
        return {"type": "object"}

    schema_type = schema.get("type", "string")

    if schema_type == "array":
        items = schema.get("items", {})
        return {
            "type": "array",
            "items": openapi_type_to_json_schema(items),
            **({"description": schema["description"]} if "description" in schema else {}),
        }

    if schema_type == "object":
        properties = {}
        for prop_name, prop_schema in schema.get("properties", {}).items():
            properties[prop_name] = openapi_type_to_json_schema(prop_schema)

        result: dict[str, Any] = {"type": "object", "properties": properties}
        if "required" in schema:
            result["required"] = schema["required"]
        if "description" in schema:
            result["description"] = schema["description"]
        return result

    # Primitive types
    result = {"type": schema_type}
    if "description" in schema:
        result["description"] = schema["description"]
    if "enum" in schema:
        result["enum"] = schema["enum"]
    if "default" in schema:
        result["default"] = schema["default"]
    if "format" in schema:
        # Map some formats
        fmt = schema["format"]
        if fmt == "date-time":
            result["description"] = result.get("description", "") + " (ISO 8601 datetime)"
        elif fmt == "uuid":
            result["description"] = result.get("description", "") + " (UUID)"

    return result


def build_tool_input_schema(endpoint: dict[str, Any]) -> dict[str, Any]:
    """Build the JSON Schema for a tool's input parameters."""
    properties: dict[str, Any] = {}
    required: list[str] = []

    # Add path/query/header parameters
    for param in endpoint["parameters"]:
        param_name = param["name"]
        param_schema = openapi_type_to_json_schema(param.get("schema", {"type": "string"}))

        # Add location info to description
        location = param["in"]
        desc = param.get("description", "")
        if location != "query":  # query is the default assumption
            desc = f"[{location}] {desc}".strip()
        if desc:
            param_schema["description"] = desc

        properties[param_name] = param_schema
        if param.get("required"):
            required.append(param_name)

    # Add request body parameters
    if endpoint["request_body"]:
        rb = endpoint["request_body"]
        rb_schema = rb.get("schema", {})

        if rb_schema.get("type") == "object" and "properties" in rb_schema:
            # Flatten body properties into tool params with 'body_' prefix
            for prop_name, prop_schema in rb_schema["properties"].items():
                full_name = f"body_{prop_name}"
                properties[full_name] = openapi_type_to_json_schema(prop_schema)
                if prop_name in rb_schema.get("required", []):
                    required.append(full_name)
        else:
            # Single body parameter
            properties["body"] = openapi_type_to_json_schema(rb_schema)
            if rb.get("required"):
                required.append("body")

    result: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        result["required"] = required

    return result


def generate_tool_definitions(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate MCP tool definitions from endpoints."""
    tools = []

    for endpoint in endpoints:
        tool = {
            "name": endpoint["tool_name"],
            "description": endpoint["description"] or f"{endpoint['method']} {endpoint['path']}",
            "inputSchema": build_tool_input_schema(endpoint),
            # Store metadata for execution
            "_endpoint": {
                "method": endpoint["method"],
                "path": endpoint["path"],
                "parameters": endpoint["parameters"],
                "request_body": endpoint["request_body"],
            },
        }
        tools.append(tool)

    return tools
