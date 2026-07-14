# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AppShield, please report it responsibly. **Do not open a public GitHub issue.**

### Reporting Process

Email: **security@example.com** *(replace with your actual security contact)*

Include the following in your report:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential mitigations

### Response Timeline

- **Within 48 hours**: Acknowledgment of receipt
- **Within 7 days**: Initial assessment and severity classification
- **Within 30 days**: Fix released or mitigation plan shared

### Scope

Security concerns related to AppShield itself (the scanner tool). Vulnerabilities found *by* AppShield in scanned code should be addressed in the scanned project, not reported here.

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Security Design

AppShield is a scanning tool that:
- Reads local files for analysis
- Sends code snippets to the Anthropic Claude API
- Never stores or transmits code to any other service
- Requires an `ANTHROPIC_API_KEY` environment variable

**Important**: Review your organization's data handling policies before scanning proprietary code with any cloud-based AI tool.
