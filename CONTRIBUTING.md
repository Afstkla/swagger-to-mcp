# Contributing to openapi-to-mcp

Thank you for your interest in contributing to openapi-to-mcp! This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- Python 3.11 or higher
- [uv](https://docs.astral.sh/uv/) - Fast Python package manager

### Setting Up Your Environment

1. **Clone the repository:**

   ```bash
   git clone https://github.com/afstkla/openapi-to-mcp.git
   cd openapi-to-mcp
   ```

2. **Install dependencies with uv:**

   ```bash
   uv sync --dev
   ```

   This will create a virtual environment and install all dependencies including development tools.

3. **Verify your setup:**

   ```bash
   uv run openapi-to-mcp --help
   ```

## Running Tests

We use pytest for testing. Run the test suite with:

```bash
# Run all tests
uv run pytest

# Run with coverage report
uv run pytest --cov=src/openapi_to_mcp --cov-report=term-missing

# Run a specific test file
uv run pytest tests/test_parser.py

# Run tests matching a pattern
uv run pytest -k "test_auth"

# Run with verbose output
uv run pytest -v
```

## Running Linting

We use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
# Check for linting errors
uv run ruff check .

# Auto-fix linting errors where possible
uv run ruff check --fix .

# Format code
uv run ruff format .

# Check formatting without making changes
uv run ruff format --check .
```

## Code Style Guidelines

- **Line length:** 100 characters maximum
- **Python version:** Target Python 3.11+
- **Type hints:** Use type hints for function signatures
- **Docstrings:** Use docstrings for public functions and classes
- **Imports:** Let Ruff organize imports (run `ruff check --fix`)

### Example

```python
def parse_openapi_spec(spec_path: str | Path) -> dict[str, Any]:
    """Parse an OpenAPI spec from a file path or URL.

    Args:
        spec_path: Path to the OpenAPI spec file (JSON or YAML) or URL.

    Returns:
        Parsed OpenAPI spec as a dictionary.

    Raises:
        ValueError: If the spec cannot be parsed.
    """
    ...
```

## Pull Request Process

1. **Create a branch:**

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and ensure:
   - All tests pass: `uv run pytest`
   - Code is linted: `uv run ruff check .`
   - Code is formatted: `uv run ruff format .`

3. **Write tests** for new functionality.

4. **Commit your changes** with a clear commit message:

   ```bash
   git commit -m "Add support for OAuth2 implicit flow"
   ```

5. **Push and create a PR:**

   ```bash
   git push origin feature/your-feature-name
   ```

6. **Fill out the PR template** with:
   - Summary of changes
   - Motivation/linked issues
   - Testing performed

7. **Address review feedback** promptly.

## Bug Reporting Requirements

When reporting bugs, you **must include**:

1. **Your OpenAPI/Swagger spec** (or a minimal version that reproduces the issue)
   - Remove sensitive data (API keys, internal endpoints)
   - Reduce to the smallest spec that still triggers the bug

2. **The exact command** you ran

3. **The full error output**

4. **Version information:**
   - Python version
   - openapi-to-mcp version (`uvx openapi-to-mcp --version`)

Without the OpenAPI spec, we cannot reproduce or fix the issue.

### Example Bug Report

```
**Bug:** Parser fails on OpenAPI 3.1 specs with webhooks

**Spec (minimal):**
```yaml
openapi: "3.1.0"
info:
  title: Test API
  version: "1.0"
webhooks:
  newUser:
    post:
      summary: New user signup
      ...
```

**Command:**
```bash
uvx openapi-to-mcp list-endpoints ./spec.yaml
```

**Error:**
```
KeyError: 'paths'
```

**Versions:** Python 3.12, openapi-to-mcp 0.1.0
```

## Project Structure

```
openapi-to-mcp/
├── src/openapi_to_mcp/
│   ├── __init__.py
│   ├── cli.py          # Command-line interface
│   ├── parser.py       # OpenAPI spec parsing
│   ├── generator.py    # MCP tool generation
│   ├── server.py       # MCP server implementation
│   └── auth.py         # Authentication handlers
├── tests/
│   ├── conftest.py     # Test fixtures
│   └── fixtures/       # Test OpenAPI specs
├── pyproject.toml
└── README.md
```

## Getting Help

- **Questions:** Open a [Discussion](https://github.com/afstkla/openapi-to-mcp/discussions)
- **Bugs:** Open an [Issue](https://github.com/afstkla/openapi-to-mcp/issues) (with your spec!)
- **Features:** Open an [Issue](https://github.com/afstkla/openapi-to-mcp/issues) with the feature request template

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
