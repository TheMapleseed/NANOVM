# NanoVM

NanoVM is an enterprise-grade, rootless virtualization system built in Rust. It provides secure, isolated environments for running applications with strong security guarantees, comprehensive resource controls, and advanced networking capabilities.

## Features

- **Secure Isolation**: Multi-level isolation mechanisms with process, namespace, and VM-level sandboxing
- **Write-XOR-Execute (W^X) Memory Protection**: Prevent code injection attacks with strict memory protection policies
- **URL-Based Routing**: Host multiple websites and services within a single container
- **Mutual TLS (mTLS)**: Secure communications with TLS 1.2+ and client certificate verification
- **Resource Control**: Fine-grained memory, CPU, and I/O limitations per instance
- **Horizontal Scaling**: Create mirrors of instances with automatic state synchronization
- **API Key Management**: Comprehensive API key handling with scopes, validation, and rate limiting
- **Data Guard**: Prevent data exfiltration through comprehensive security policies
- **Observability**: Built-in metrics, tracing, and logging capabilities

## Architecture

NanoVM consists of several subsystems:

- **VM Core**: Instance management and memory protection
- **Configuration**: Structured configuration with validation
- **Network**: URL routing, proxying, and TLS termination
- **Security**: W^X enforcement, data guarding, and API key management
- **Scaling**: VM mirroring and orchestration
- **Execution Engine**: Resource-limited task execution
- **Sandbox**: Process isolation and capability control

## Getting Started

### Prerequisites

- Rust 1.54 or later
- Linux environment with namespace support
- CMake and build essentials

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/TheMapleseed/NANOVM.git
   cd NANOVM
   ```

2. Build the project:
   ```
   cargo build --release
   ```

3. Install the binary:
   ```
   cargo install --path .
   ```

## Configuration

NanoVM uses YAML for configuration. Here's a basic example:

```yaml
version: "1.0"
instance:
  memory_limit: 512mb
  cpu_limit: 2.0
  timeout_seconds: 300
  
security:
  data_guard:
    enabled: true
    outbound_whitelist:
      - "api.example.com"
      - "storage.example.net"
  wx_policy:
    strict: true
    audit_logging: true
    
network:
  urls:
    - "https://service1.example.com"
    - "https://service2.example.com"
  tls:
    enabled: true
    min_version: "1.2"
    cert_path: "/path/to/server.crt"
    key_path: "/path/to/server.key"
    enable_mtls: true
    client_ca_path: "/path/to/client-ca.crt"
    require_client_cert: true
  
scaling:
  mirrors: 3
  autoscale:
    min_instances: 2
    max_instances: 10
    cpu_threshold: 75
```

## Multi-Website Hosting

NanoVM enables hosting multiple websites within a single container through URL-based routing:

1. Configure multiple URLs in the configuration YAML
2. Each URL is associated with a specific VM instance
3. Deploy different applications in each VM instance
4. The proxy server routes requests to the appropriate instance

## Security Features

### Mutual TLS (mTLS)

NanoVM supports mutual TLS for secure service-to-service communication:

- TLS 1.2 and 1.3 support with TLS 1.2 as the enforced minimum
- Client certificate verification
- Server certificate validation
- Configurable certificate paths and verification requirements

### W^X Memory Protection

Prevents code injection attacks by ensuring that memory is either writable OR executable, never both:

- Strict mode enforcement
- Memory region-specific protection settings
- Protection violation auditing

### Data Guard

Prevents data exfiltration through comprehensive policy enforcement:

- Outbound connection controls
- Filesystem access limitations
- Instance data isolation

## Deployment

NanoVM can be deployed in various environments:

- Bare metal servers
- Kubernetes clusters (via provided manifests)
- Container platforms

For production deployments, refer to the deployment scripts in the `deploy/` directory.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE). 