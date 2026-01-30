# AGENTS.md

This file provides context and technical instructions specifically for AI coding assistants working on the `fastapi-oauth-rbac` library.

## Project Overview
`fastapi-oauth-rbac` is a FastAPI library designed to provide a comprehensive, extensible, and easy-to-use authentication and NIST-style RBAC system. It supports SQLAlchemy, Argon2 hashing (via `pwdlib`), and OAuth (Google).

## Setup & Development
This project uses `uv` for dependency management.

### Environment Setup
```bash
# Install dependencies and create virtual environment
uv sync
```

### Development Workflow
- All code must be in English.
- Use `SQLAlchemy` for database interactions.
- Ensure all new features are accompanied by tests in the `tests/` directory.

## Testing Instructions
We use `pytest` for testing.

### Running Tests
```bash
# Run all tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=fastapi_oauth_rbac
```

## Code Style & Conventions
- **Naming**: Use snake_case for functions and variables, PascalCase for classes.
- **Type Hinting**: All public APIs must have comprehensive type hints.
- **Async/Await**: Use asynchronous programming where appropriate, especially for database and network operations.
- **Security**: 
    - Use `pwdlib` with Argon2 for password hashing.
    - Implement NIST-style RBAC with hierarchy.
    - Support optional JWT revocation.

## Workflow & PR Guidelines
- **Commits**: Use descriptive commit messages.
- **PRs**: Ensure all tests pass and documentation is updated before submitting a PR.
- **Verification**: Run `uv run pytest` before finalizing any task.
