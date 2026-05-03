# Contributing to VanGuard

Thank you for your interest in contributing to VanGuard.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/vanguard.git`
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Build and verify: `go build -trimpath -o vanguard.exe ./cmd/vanguard/`
6. Commit with a descriptive message
7. Push to your fork and open a Pull Request

## Development Requirements

- Go 1.22+ with CGO enabled (required for go-sqlite3)
- GCC (MSYS2 or TDM-GCC on Windows, gcc on Linux)
- Build command: `CGO_ENABLED=1 go build -trimpath -o vanguard.exe ./cmd/vanguard/`

## Code Standards

- Go standard library preferred over external dependencies
- All SQL queries must use parameterised statements (? placeholders)
- All exec.Command calls must pass arguments as separate slice elements
- All file writes for sensitive data must use 0o600 permissions
- All output directories must use 0o700 permissions
- All user inputs must be validated before use in commands or file paths
- Run `go vet ./...` before submitting

## Security

If you discover a security vulnerability, please report it privately via GitHub's Security Advisories rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
