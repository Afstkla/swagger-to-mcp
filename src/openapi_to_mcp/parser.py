"""OpenAPI spec parser."""

import json
import re
from pathlib import Path
from typing import Any

import httpx
import yaml


def load_spec(source: str) -> dict[str, Any]:
    """Load OpenAPI spec from file path or URL."""
    if source.startswith(("http://", "https://")):
        response = httpx.get(source, timeout=30)
        response.raise_for_status()
        content = response.text
        if source.endswith(".yaml") or source.endswith(".yml"):
            return yaml.safe_load(content)
        return response.json()

    path = Path(source)
    content = path.read_text()
    if path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(content)
    return json.loads(content)


def resolve_ref(spec: dict[str, Any], ref: str) -> dict[str, Any]:
    """Resolve a $ref pointer in the spec."""
    if not ref.startswith("#/"):
        return {}
    parts = ref[2:].split("/")
    current = spec
    for part in parts:
        current = current.get(part, {})
    return current


def resolve_schema(spec: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Recursively resolve $ref in schema."""
    if not schema:
        return {}

    if "$ref" in schema:
        resolved = resolve_ref(spec, schema["$ref"])
        return resolve_schema(spec, resolved)

    if schema.get("type") == "array" and "items" in schema:
        schema = schema.copy()
        schema["items"] = resolve_schema(spec, schema["items"])

    if schema.get("type") == "object" and "properties" in schema:
        schema = schema.copy()
        schema["properties"] = {k: resolve_schema(spec, v) for k, v in schema["properties"].items()}

    if "allOf" in schema:
        merged: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
        for sub in schema["allOf"]:
            resolved = resolve_schema(spec, sub)
            if "properties" in resolved:
                merged["properties"].update(resolved["properties"])
            if "required" in resolved:
                merged["required"].extend(resolved["required"])
        return merged

    if "anyOf" in schema:
        # Take first non-null option
        for sub in schema["anyOf"]:
            resolved = resolve_schema(spec, sub)
            if resolved.get("type") != "null":
                return resolved
        return schema["anyOf"][0] if schema["anyOf"] else {}

    if "oneOf" in schema:
        return resolve_schema(spec, schema["oneOf"][0]) if schema["oneOf"] else {}

    return schema


def _clean_operation_id(operation_id: str) -> str:
    """Clean up an operationId to be a valid tool name.

    Converts camelCase to snake_case, replaces hyphens with underscores.
    """
    # Replace hyphens with underscores
    name = operation_id.replace("-", "_")
    # Convert camelCase to snake_case
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    # Clean up multiple underscores
    name = re.sub(r"_+", "_", name).strip("_")
    return name


def make_tool_name(method: str, path: str, operation_id: str | None) -> str:
    """Generate a clean tool name from the operation.

    If operationId is provided in the spec, it is used (cleaned up to snake_case).
    Otherwise generates names like:
    - GET /v1/skills/ -> list_skills
    - POST /v1/skills/ -> create_skill
    - GET /v1/skills/{id} -> get_skill
    - PATCH /v1/skills/{id} -> update_skill
    - DELETE /v1/skills/{id} -> delete_skill
    """
    # Use operationId if provided
    if operation_id:
        return _clean_operation_id(operation_id)

    # Clean up path: remove version prefix, extract meaningful parts
    clean_path = re.sub(r"^/v\d+/", "/", path)  # Remove /v1/, /v2/ etc
    segments = [s for s in clean_path.split("/") if s and not s.startswith("{")]

    if not segments:
        segments = ["root"]

    # Determine the action based on method and path pattern
    has_id = bool(re.search(r"\{[^}]+\}$", path))  # Ends with {id} or {something_id}
    resource = segments[-1].replace("-", "_")

    # Singularize if operating on specific item
    if has_id and resource.endswith("s") and len(resource) > 2:
        resource_singular = resource[:-1] if not resource.endswith("ss") else resource
    else:
        resource_singular = resource

    # Map method to verb
    if method.lower() == "get":
        verb = "get" if has_id else "list"
    elif method.lower() == "post":
        verb = "create"
    elif method.lower() == "put":
        verb = "replace"
    elif method.lower() == "patch":
        verb = "update"
    elif method.lower() == "delete":
        verb = "delete"
    else:
        verb = method.lower()

    # Build name: verb_[parent_]resource
    target = resource_singular if has_id else resource
    if len(segments) > 1:
        parent = segments[-2].replace("-", "_")
        # Avoid redundancy
        if parent != resource:
            action = f"{verb}_{parent}_{target}"
        else:
            action = f"{verb}_{target}"
    else:
        action = f"{verb}_{target}"

    # Clean up
    action = re.sub(r"_+", "_", action).strip("_")

    return action


def extract_endpoints(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract all endpoints from the OpenAPI spec."""
    endpoints = []
    used_names: dict[str, int] = {}
    paths = spec.get("paths", {})
    for path, path_item in paths.items():
        for method in ["get", "post", "put", "patch", "delete"]:
            if method not in path_item:
                continue

            operation = path_item[method]
            operation_id = operation.get("operationId")
            tool_name = make_tool_name(method, path, operation_id)

            # Handle duplicates by adding suffix
            if tool_name in used_names:
                used_names[tool_name] += 1
                tool_name = f"{tool_name}_{used_names[tool_name]}"
            else:
                used_names[tool_name] = 1

            # Extract parameters
            parameters = []
            for param in operation.get("parameters", []) + path_item.get("parameters", []):
                if "$ref" in param:
                    param = resolve_ref(spec, param["$ref"])

                param_schema = resolve_schema(spec, param.get("schema", {}))
                parameters.append(
                    {
                        "name": param["name"],
                        "in": param["in"],  # path, query, header, cookie
                        "required": param.get("required", False),
                        "description": param.get("description", ""),
                        "schema": param_schema,
                    }
                )

            # Extract request body
            request_body = None
            if "requestBody" in operation:
                rb = operation["requestBody"]
                content = rb.get("content", {})
                # Prefer JSON
                for content_type in ["application/json", "application/x-www-form-urlencoded"]:
                    if content_type in content:
                        schema = content[content_type].get("schema", {})
                        request_body = {
                            "content_type": content_type,
                            "required": rb.get("required", False),
                            "schema": resolve_schema(spec, schema),
                        }
                        break

            # Extract response schema (for documentation)
            response_schema = None
            responses = operation.get("responses", {})
            for status in ["200", "201", "204"]:
                if status in responses:
                    resp = responses[status]
                    content = resp.get("content", {})
                    if "application/json" in content:
                        response_schema = resolve_schema(
                            spec, content["application/json"].get("schema", {})
                        )
                    break

            # Build description
            summary = operation.get("summary", "")
            description = operation.get("description", "")
            full_description = f"{summary}\n\n{description}".strip() if description else summary

            endpoints.append(
                {
                    "tool_name": tool_name,
                    "method": method.upper(),
                    "path": path,
                    "operation_id": operation_id,
                    "tags": operation.get("tags", []),
                    "summary": summary,
                    "description": full_description,
                    "parameters": parameters,
                    "request_body": request_body,
                    "response_schema": response_schema,
                    "security": operation.get("security", []),
                }
            )

    return endpoints
