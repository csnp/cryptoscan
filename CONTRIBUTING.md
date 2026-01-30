# Contributing to Crypto Scan

Thank you for your interest in contributing to Crypto Scan! This project is part of the QRAMM toolkit by CSNP, and we welcome contributions from the community.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists in [GitHub Issues](https://github.com/csnp/cryptoscan/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Go version)
   - Sample code or files if applicable

### Suggesting Features

Open an issue with the `enhancement` label describing:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

### Pull Requests

1. **Fork the repository**

2. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Run tests**
   ```bash
   go test -race ./...
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m "Add: description of what you added"
   git commit -m "Fix: description of what you fixed"
   git commit -m "Update: description of what you changed"
   ```

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Go 1.21 or later
- Git

### Building

```bash
git clone https://github.com/csnp/cryptoscan.git
cd cryptoscan
go build -o cryptoscan ./cmd/cryptoscan
```

### Running Tests

```bash
# All tests
go test ./...

# With race detection
go test -race ./...

# With coverage
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Project Structure

```
├── cmd/cryptoscan/      # CLI entry point
├── internal/cli/        # CLI commands
├── pkg/
│   ├── analyzer/        # File and context analysis
│   ├── patterns/        # Crypto pattern definitions
│   ├── reporter/        # Output formatters
│   ├── scanner/         # Core scanning logic
│   └── types/           # Shared types
```

## Adding New Patterns

To add new cryptographic detection patterns:

1. Edit `pkg/patterns/matcher.go`
2. Add a new `Pattern` struct with:
   - Unique ID (e.g., "RSA-001")
   - Descriptive name
   - Category
   - Compiled regex
   - Severity level
   - Quantum risk classification
   - Description and remediation guidance

3. Add tests in `pkg/patterns/matcher_test.go`

Example:
```go
{
    ID:          "NEW-001",
    Name:        "New Pattern Name",
    Category:    "Category Name",
    Regex:       regexp.MustCompile(`your-regex-here`),
    Severity:    types.SeverityHigh,
    Quantum:     types.QuantumVulnerable,
    Algorithm:   "AlgorithmName",
    Description: "What this pattern detects",
    Remediation: "How to fix it",
}
```

## Style Guidelines

- Follow standard Go conventions
- Use `gofmt` for formatting
- Keep functions focused and small
- Add comments for exported functions
- Prefer clarity over cleverness

## Testing Guidelines

- Write table-driven tests where appropriate
- Test both positive and negative cases
- Include edge cases
- Aim for meaningful coverage, not just percentage

## Questions?

- Open an issue for questions
- Join discussions in existing issues
- Reach out via [CSNP](https://csnp.org)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
