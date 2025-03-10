# Contributing to NanoVM

Thank you for your interest in contributing to NanoVM! We welcome contributions from the community to make this project better.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

- Check if the bug has already been reported in the Issues section
- Use the bug report template when creating a new issue
- Include detailed steps to reproduce the bug
- Specify your environment (OS, Rust version, etc.)

### Suggesting Features

- Check if the feature has already been suggested in the Issues section
- Use the feature request template when creating a new issue
- Explain the feature's value and potential implementation approach

### Code Contributions

1. Fork the repository
2. Create a new branch for your feature or bugfix (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Run tests to ensure no regressions (`cargo test`)
5. Update documentation as needed
6. Commit your changes with a descriptive message
7. Push to your branch (`git push origin feature/your-feature-name`)
8. Open a Pull Request

## Development Guidelines

### Code Style

- Follow the Rust style guidelines
- Use `cargo fmt` before committing
- Use `cargo clippy` to check for common issues

### Testing

- Add tests for new functionality
- Ensure all tests pass before submitting a PR
- Write both unit tests and integration tests when appropriate

### Security Considerations

- Be cautious with dependencies and use audited versions
- Follow secure coding practices
- Consider the security implications of all changes
- Document security-critical components

### Documentation

- Update README.md with any necessary changes
- Document new features or behavioral changes
- Add inline documentation for new functions and methods

## Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update the CHANGELOG.md with details of changes
3. The PR will be merged once it receives approval from maintainers

## Branching Strategy

- `main`: Production-ready code
- `develop`: Latest development changes
- Feature branches: `feature/feature-name`
- Bugfix branches: `bugfix/issue-description`

## License

By contributing to NanoVM, you agree that your contributions will be licensed under the project's [GNU GPL v3.0 License](LICENSE). 