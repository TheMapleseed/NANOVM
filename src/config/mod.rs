// src/config/mod.rs

pub mod schema;
pub mod validator;

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::security::data_guard::{DataGuardConfig, ApiKeyConfig};
use crate::security::wx_enforcer::MemoryProtection;

/// Comprehensive configuration for a NanoVM instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Configuration format version
    pub version: String,
    
    /// Base resource configuration
    pub resources: ResourceConfig,
    
    /// Security configuration
    pub security: SecurityConfig,
    
    /// Network configuration
    pub network: NetworkConfig,
    
    /// Scaling configuration
    pub scaling: ScalingConfig,
    
    /// Secret management configuration
    pub secrets: SecretsConfig,
    
    /// Observability configuration
    pub observability: ObservabilityConfig,
}

/// Resource allocation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    /// Memory limit in bytes
    pub memory_limit_bytes: u64,
    
    /// CPU limit in cores (can be fractional)
    pub cpu_limit: f64,
    
    /// Maximum execution time in seconds (0 = unlimited)
    pub timeout_seconds: u64,
    
    /// Storage limit in bytes
    pub storage_limit_bytes: u64,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Data Guard configuration
    pub data_guard: DataGuardConfig,
    
    /// W^X memory protection configuration
    pub wx_policy: WxPolicyConfig,
    
    /// Sandboxing configuration
    pub sandbox: SandboxConfig,
}

/// W^X policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WxPolicyConfig {
    /// Whether to enforce strict W^X (no exceptions)
    pub strict: bool,
    
    /// Whether to enable audit logging for memory operations
    pub audit_logging: bool,
    
    /// Default protection for newly allocated memory
    pub default_protection: MemoryProtectionMode,
    
    /// Memory regions with specific protection settings
    pub memory_regions: Vec<MemoryRegionConfig>,
}

/// Memory protection mode (serializable version of MemoryProtection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryProtectionMode {
    /// Read-only memory
    ReadOnly,
    
    /// Read-write memory (no execution)
    ReadWrite,
    
    /// Executable memory (no write)
    Executable,
}

impl From<MemoryProtectionMode> for MemoryProtection {
    fn from(mode: MemoryProtectionMode) -> Self {
        match mode {
            MemoryProtectionMode::ReadOnly => MemoryProtection::ReadOnly,
            MemoryProtectionMode::ReadWrite => MemoryProtection::ReadWrite,
            MemoryProtectionMode::Executable => MemoryProtection::Executable,
        }
    }
}

/// Memory region configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionConfig {
    /// Name of the memory region
    pub name: String,
    
    /// Base address (0 = let system decide)
    pub base_address: usize,
    
    /// Size in bytes
    pub size_bytes: usize,
    
    /// Protection mode
    pub protection: MemoryProtectionMode,
}

/// Sandboxing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Whether to enable the sandbox
    pub enabled: bool,
    
    /// Whether to allow system calls
    pub allow_syscalls: bool,
    
    /// List of allowed system calls (if any)
    pub allowed_syscalls: Vec<String>,
    
    /// Whether to enable seccomp filtering
    pub enable_seccomp: bool,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// List of URLs to associate with this VM
    pub urls: Vec<String>,
    
    /// Network interface configuration
    pub interface: NetworkInterfaceConfig,
    
    /// TLS/SSL configuration
    pub tls: TlsConfig,
}

/// Network interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceConfig {
    /// Whether to enable inbound connections
    pub enable_inbound: bool,
    
    /// Whether to enable outbound connections
    pub enable_outbound: bool,
    
    /// Listen port for inbound connections
    pub listen_port: u16,
    
    /// Maximum number of concurrent connections
    pub max_connections: u32,
    
    /// Connection timeout in seconds
    pub connection_timeout_seconds: u32,
}

/// TLS/SSL configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Whether to enable TLS
    pub enabled: bool,
    
    /// Path to certificate file
    pub cert_path: Option<String>,
    
    /// Path to private key file
    pub key_path: Option<String>,
    
    /// Minimum TLS version
    pub min_version: TlsVersion,
    
    /// Whether to enable mutual TLS (client certificate verification)
    pub enable_mtls: bool,
    
    /// Path to CA certificate file for client verification
    pub client_ca_path: Option<String>,
    
    /// Whether to require client certificate verification
    pub require_client_cert: bool,
}

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.0 (not recommended)
    #[serde(rename = "1.0")]
    V1_0,
    
    /// TLS 1.1 (not recommended)
    #[serde(rename = "1.1")]
    V1_1,
    
    /// TLS 1.2
    #[serde(rename = "1.2")]
    V1_2,
    
    /// TLS 1.3 (recommended)
    #[serde(rename = "1.3")]
    V1_3,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            min_version: TlsVersion::V1_2, // Ensure TLS 1.2 is the minimum by default
            enable_mtls: false,
            client_ca_path: None,
            require_client_cert: false,
        }
    }
}

/// Scaling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingConfig {
    /// Number of mirror instances to create
    pub mirrors: u32,
    
    /// Autoscaling configuration
    pub autoscale: AutoscaleConfig,
    
    /// State synchronization configuration
    pub state_sync: StateSyncConfig,
}

/// Autoscaling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoscaleConfig {
    /// Whether to enable autoscaling
    pub enabled: bool,
    
    /// Minimum number of instances
    pub min_instances: u32,
    
    /// Maximum number of instances
    pub max_instances: u32,
    
    /// CPU utilization threshold for scaling (percentage)
    pub cpu_threshold: u32,
    
    /// Cooldown period between scaling operations (seconds)
    pub cooldown_seconds: u32,
}

/// State synchronization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncConfig {
    /// Synchronization interval in milliseconds
    pub sync_interval_ms: u64,
    
    /// Maximum sync delta size in bytes
    pub max_delta_size_bytes: u64,
    
    /// Whether to enable conflict resolution
    pub enable_conflict_resolution: bool,
}

/// Secret management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// API key configurations
    pub api_keys: Vec<ApiKeyReference>,
    
    /// Environment variable secrets
    pub env_vars: Vec<EnvVarReference>,
}

/// API key reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyReference {
    /// Name of the API key
    pub name: String,
    
    /// Source of the API key value
    pub value_from: SecretSource,
}

/// Environment variable reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarReference {
    /// Name of the environment variable
    pub name: String,
    
    /// Source of the environment variable value
    pub value_from: SecretSource,
}

/// Secret source specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecretSource {
    /// Direct value (not recommended for production)
    #[serde(rename = "value")]
    Value(String),
    
    /// Reference to an external source
    #[serde(rename = "source")]
    Reference(String),
}

/// Observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Metrics collection configuration
    pub metrics: MetricsConfig,
    
    /// Tracing configuration
    pub tracing: TracingConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Metrics collection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Whether to enable metrics collection
    pub enabled: bool,
    
    /// Metrics collection interval in seconds
    pub interval_seconds: u32,
    
    /// Exporters configuration
    pub exporters: Vec<ExporterConfig>,
}

/// Metrics exporter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExporterConfig {
    /// Exporter type
    pub type_: String,
    
    /// Exporter endpoint
    pub endpoint: String,
    
    /// Additional exporter configuration
    pub config: HashMap<String, String>,
}

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Whether to enable distributed tracing
    pub enabled: bool,
    
    /// Sampling rate (0.0-1.0)
    pub sampling_rate: f64,
    
    /// Exporter configuration
    pub exporter: Option<ExporterConfig>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: LogLevel,
    
    /// Whether to log to stdout
    pub log_to_stdout: bool,
    
    /// Whether to log to file
    pub log_to_file: bool,
    
    /// Log file path (if log_to_file is true)
    pub log_file: Option<String>,
    
    /// Log format
    pub format: LogFormat,
}

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    /// Error level
    Error,
    
    /// Warning level
    Warning,
    
    /// Info level
    Info,
    
    /// Debug level
    Debug,
    
    /// Trace level
    Trace,
}

/// Log format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogFormat {
    /// Plain text
    Plain,
    
    /// JSON format
    Json,
    
    /// Structured format
    Structured,
}

/// Configuration manager
pub struct ConfigManager {
    /// Current active configuration
    config: VmConfig,
    
    /// Configuration file path
    config_path: Option<String>,
    
    /// Whether the configuration has been validated
    validated: bool,
}

impl ConfigManager {
    /// Creates a new configuration manager with a default configuration
    pub fn new() -> Self {
        Self {
            config: Self::default_config(),
            config_path: None,
            validated: false,
        }
    }
    
    /// Loads configuration from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let config_str = fs::read_to_string(&path)
            .map_err(|e| ConfigError::FileReadError {
                path: path.as_ref().to_string_lossy().into_owned(),
                error: e.to_string(),
            })?;
            
        let config: VmConfig = serde_yaml::from_str(&config_str)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
            
        let mut manager = Self {
            config,
            config_path: Some(path.as_ref().to_string_lossy().into_owned()),
            validated: false,
        };
        
        // Validate the configuration
        manager.validate()?;
        
        info!("Configuration loaded from {}", path.as_ref().display());
        
        Ok(manager)
    }
    
    /// Saves the current configuration to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let config_str = serde_yaml::to_string(&self.config)
            .map_err(|e| ConfigError::SerializationError(e.to_string()))?;
            
        fs::write(&path, config_str)
            .map_err(|e| ConfigError::FileWriteError {
                path: path.as_ref().to_string_lossy().into_owned(),
                error: e.to_string(),
            })?;
            
        info!("Configuration saved to {}", path.as_ref().display());
        
        Ok(())
    }
    
    /// Validates the current configuration
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        // Initialize the validator
        let validator = validator::ConfigValidator::new();
        
        // Validate the configuration
        validator.validate(&self.config)?;
        
        self.validated = true;
        debug!("Configuration validated successfully");
        
        Ok(())
    }
    
    /// Gets the current configuration
    pub fn get_config(&self) -> &VmConfig {
        &self.config
    }
    
    /// Updates the current configuration
    pub fn update_config(&mut self, config: VmConfig) -> Result<(), ConfigError> {
        // Store the new configuration
        self.config = config;
        
        // Validate the new configuration
        self.validate()?;
        
        Ok(())
    }
    
    /// Resolves secrets in the configuration
    pub fn resolve_secrets(&mut self) -> Result<(), ConfigError> {
        // Resolve API key secrets
        for api_key_ref in &self.config.secrets.api_keys {
            let value = self.resolve_secret_source(&api_key_ref.value_from)?;
            debug!("Resolved API key: {}", api_key_ref.name);
            
            // The resolved secrets would be stored in a secure way and used by the
            // API key management system - details omitted for brevity
        }
        
        // Resolve environment variable secrets
        for env_var_ref in &self.config.secrets.env_vars {
            let value = self.resolve_secret_source(&env_var_ref.value_from)?;
            debug!("Resolved environment variable: {}", env_var_ref.name);
            
            // The resolved secrets would be stored securely and used by the
            // environment setup system - details omitted for brevity
        }
        
        Ok(())
    }
    
    /// Resolves a secret source to its actual value
    fn resolve_secret_source(&self, source: &SecretSource) -> Result<String, ConfigError> {
        match source {
            SecretSource::Value(value) => {
                // Direct value - use as is
                Ok(value.clone())
            }
            SecretSource::Reference(reference) => {
                // Parse the reference format: source:path
                let parts: Vec<&str> = reference.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return Err(ConfigError::InvalidSecretReference(reference.clone()));
                }
                
                let source_type = parts[0];
                let source_path = parts[1];
                
                match source_type {
                    "env" => {
                        // Get from environment variable
                        std::env::var(source_path)
                            .map_err(|_| ConfigError::SecretResolutionError {
                                source: reference.clone(),
                                error: format!("Environment variable {} not found", source_path),
                            })
                    }
                    "file" => {
                        // Read from file
                        fs::read_to_string(source_path)
                            .map_err(|e| ConfigError::SecretResolutionError {
                                source: reference.clone(),
                                error: format!("Failed to read file {}: {}", source_path, e),
                            })
                            .map(|s| s.trim().to_string())
                    }
                    "vault" => {
                        // Vault integration would go here
                        // For now, we'll return an error
                        Err(ConfigError::SecretResolutionError {
                            source: reference.clone(),
                            error: "Vault integration not implemented".to_string(),
                        })
                    }
                    _ => {
                        Err(ConfigError::InvalidSecretSource(source_type.to_string()))
                    }
                }
            }
        }
    }
    
    /// Creates a default configuration
    fn default_config() -> VmConfig {
        VmConfig {
            version: "1.0".to_string(),
            resources: ResourceConfig {
                memory_limit_bytes: 512 * 1024 * 1024, // 512 MB
                cpu_limit: 1.0,
                timeout_seconds: 300,
                storage_limit_bytes: 1024 * 1024 * 1024, // 1 GB
            },
            security: SecurityConfig {
                data_guard: DataGuardConfig {
                    enabled: true,
                    outbound_network: crate::security::data_guard::OutboundNetworkConfig {
                        allow_outbound: false,
                        allowed_hostnames: vec![],
                        allowed_ips: vec![],
                        allowed_ports: vec![],
                        bandwidth_limit_bps: 0,
                    },
                    filesystem: crate::security::data_guard::FilesystemConfig {
                        allow_filesystem: false,
                        storage_limit_bytes: 0,
                        allowed_paths: vec![],
                        allow_writes: false,
                    },
                    isolation: crate::security::data_guard::IsolationPolicy {
                        strict_isolation: true,
                        allow_instance_data_sharing: false,
                        max_data_classification: 0,
                    },
                    auditing: crate::security::data_guard::AuditConfig {
                        enabled: true,
                        retention_days: 30,
                        log_all_access: false,
                    },
                },
                wx_policy: WxPolicyConfig {
                    strict: true,
                    audit_logging: true,
                    default_protection: MemoryProtectionMode::ReadOnly,
                    memory_regions: vec![],
                },
                sandbox: SandboxConfig {
                    enabled: true,
                    allow_syscalls: false,
                    allowed_syscalls: vec![],
                    enable_seccomp: true,
                },
            },
            network: NetworkConfig {
                urls: vec![],
                interface: NetworkInterfaceConfig {
                    enable_inbound: true,
                    enable_outbound: false,
                    listen_port: 8080,
                    max_connections: 1000,
                    connection_timeout_seconds: 30,
                },
                tls: TlsConfig {
                    enabled: true,
                    cert_path: None,
                    key_path: None,
                    min_version: TlsVersion::V1_3,
                    enable_mtls: false,
                    client_ca_path: None,
                    require_client_cert: false,
                },
            },
            scaling: ScalingConfig {
                mirrors: 0,
                autoscale: AutoscaleConfig {
                    enabled: false,
                    min_instances: 1,
                    max_instances: 1,
                    cpu_threshold: 80,
                    cooldown_seconds: 60,
                },
                state_sync: StateSyncConfig {
                    sync_interval_ms: 1000,
                    max_delta_size_bytes: 1024 * 1024, // 1 MB
                    enable_conflict_resolution: true,
                },
            },
            secrets: SecretsConfig {
                api_keys: vec![],
                env_vars: vec![],
            },
            observability: ObservabilityConfig {
                metrics: MetricsConfig {
                    enabled: true,
                    interval_seconds: 15,
                    exporters: vec![],
                },
                tracing: TracingConfig {
                    enabled: true,
                    sampling_rate: 0.1,
                    exporter: None,
                },
                logging: LoggingConfig {
                    level: LogLevel::Info,
                    log_to_stdout: true,
                    log_to_file: false,
                    log_file: None,
                    format: LogFormat::Json,
                },
            },
        }
    }
}

/// Configuration validation errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read configuration file {path}: {error}")]
    FileReadError {
        path: String,
        error: String,
    },
    
    #[error("Failed to write configuration file {path}: {error}")]
    FileWriteError {
        path: String,
        error: String,
    },
    
    #[error("Failed to parse configuration: {0}")]
    ParseError(String),
    
    #[error("Failed to serialize configuration: {0}")]
    SerializationError(String),
    
    #[error("Invalid configuration: {0}")]
    ValidationError(String),
    
    #[error("Invalid secret reference: {0}")]
    InvalidSecretReference(String),
    
    #[error("Invalid secret source: {0}")]
    InvalidSecretSource(String),
    
    #[error("Failed to resolve secret {source}: {error}")]
    SecretResolutionError {
        source: String,
        error: String,
    },
}

// src/config/validator.rs
pub struct ConfigValidator {
    // Validator implementation details omitted for brevity
}

impl ConfigValidator {
    pub fn new() -> Self {
        Self {}
    }
    
    pub fn validate(&self, config: &VmConfig) -> Result<(), ConfigError> {
        // Basic version check
        if !config.version.starts_with("1.") {
            return Err(ConfigError::ValidationError(
                format!("Unsupported configuration version: {}", config.version)
            ));
        }
        
        // Validate resources
        self.validate_resources(&config.resources)?;
        
        // Validate security
        self.validate_security(&config.security)?;
        
        // Validate network
        self.validate_network(&config.network)?;
        
        // Validate scaling
        self.validate_scaling(&config.scaling)?;
        
        // Validate secrets
        self.validate_secrets(&config.secrets)?;
        
        // Validate observability
        self.validate_observability(&config.observability)?;
        
        Ok(())
    }
    
    fn validate_resources(&self, resources: &ResourceConfig) -> Result<(), ConfigError> {
        // Check memory limit
        if resources.memory_limit_bytes == 0 {
            return Err(ConfigError::ValidationError(
                "Memory limit must be greater than zero".to_string()
            ));
        }
        
        // Check CPU limit
        if resources.cpu_limit <= 0.0 {
            return Err(ConfigError::ValidationError(
                "CPU limit must be greater than zero".to_string()
            ));
        }
        
        // Additional resource validation would go here
        
        Ok(())
    }
    
    // Other validation methods omitted for brevity
    fn validate_security(&self, _security: &SecurityConfig) -> Result<(), ConfigError> {
        // Security validation logic
        Ok(())
    }
    
    fn validate_network(&self, _network: &NetworkConfig) -> Result<(), ConfigError> {
        // Network validation logic
        Ok(())
    }
    
    fn validate_scaling(&self, _scaling: &ScalingConfig) -> Result<(), ConfigError> {
        // Scaling validation logic
        Ok(())
    }
    
    fn validate_secrets(&self, _secrets: &SecretsConfig) -> Result<(), ConfigError> {
        // Secrets validation logic
        Ok(())
    }
    
    fn validate_observability(&self, _observability: &ObservabilityConfig) -> Result<(), ConfigError> {
        // Observability validation logic
        Ok(())
    }
}

System Integration

Finally, let's tie everything together with a minimal main entry point to demonstrate how all the components integrate seamlessly:

rust

// src/main.rs

use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::sync::mpsc;
use tracing::{error, info};
use uuid::Uuid;

use nanovm::config::{ConfigManager, VmConfig};
use nanovm::vm::Instance;
use nanovm::network::UrlResolver;
use nanovm::security::{DataGuard, WxEnforcer};
use nanovm::scaling::MirrorManager;

#[derive(Debug, StructOpt)]
#[structopt(name = "nanovm", about = "Enterprise-grade rootless virtualization system")]
struct Opt {
    /// Path to configuration file
    #[structopt(short, long, parse(from_os_str))]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    
    // Parse command-line arguments
    let opt = Opt::from_args();
    
    // Load configuration
    let mut config_manager = ConfigManager::load_from_file(&opt.config)?;
    
    // Resolve secrets
    config_manager.resolve_secrets()?;
    
    // Get the final configuration
    let config = config_manager.get_config().clone();
    
    // Initialize the URL resolver
    let url_resolver = Arc::new(UrlResolver::new());
    
    // Initialize security subsystems
    let (data_guard, security_events_rx) = DataGuard::new(config.security.data_guard.clone())?;
    let wx_enforcer = WxEnforcer::new();
    
    // Start security event monitoring
    tokio::spawn(monitor_security_events(security_events_rx));
    
    // Create the primary VM instance
    let primary_instance = Instance::new(config.clone()).await?;
    
    // Create the mirror manager if mirrors are specified
    if config.scaling.mirrors > 0 {
        let mirror_manager = MirrorManager::new(primary_instance.clone());
        
        // Create mirror instances
        for _ in 0..config.scaling.mirrors {
            let mirror_instance = mirror_manager.add_mirror(config.clone()).await?;
            info!("Created mirror instance: {}", mirror_instance.read().unwrap().id);
        }
        
        // Associate URLs
        for url in &config.network.urls {
            mirror_manager.associate_url(url).await?;
            info!("Associated URL with all instances: {}", url);
        }
    } else {
        // Associate URLs with the primary instance only
        for url in &config.network.urls {
            let mut instance = primary_instance.write().unwrap();
            instance.associate_url(url).await?;
            info!("Associated URL with primary instance: {}", url);
        }
    }
    
    // Start the primary instance
    {
        let mut instance = primary_instance.write().unwrap();
        instance.start().await?;
        info!("Started primary instance: {}", instance.id);
    }
    
    // Wait for termination signal
    tokio::signal::ctrl_c().await?;
    
    // Terminate the instance
    {
        let mut instance = primary_instance.write().unwrap();
        instance.terminate().await?;
        info!("Terminated primary instance: {}", instance.id);
    }
    
    Ok(())
}

/// Monitors security events from the DataGuard
async fn monitor_security_events(mut rx: mpsc::Receiver<SecurityEvent>) {
    while let Some(event) = rx.recv().await {
        match event.severity {
            SecurityEventSeverity::Info => {
                info!(
                    event_id = %event.id,
                    category = %event.category,
                    "SECURITY: {}",
                    event.description
                );
            }
            SecurityEventSeverity::Warning => {
                tracing::warn!(
                    event_id = %event.id,
                    category = %event.category,
                    "SECURITY WARNING: {}",
                    event.description
                );
            }
            SecurityEventSeverity::Critical => {
                error!(
                    event_id = %event.id,
                    category = %event.category,
                    "SECURITY CRITICAL: {}",
                    event.description
                );
                
                // Additional alerting or response actions could be triggered here
            }
        }
    }
}

Deployment Example

Here's a complete deployment example using Kubernetes manifests:

yaml

# deploy/k8s/nanovm-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nanovm-service
  labels:
    app: nanovm-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nanovm-service
  template:
    metadata:
      labels:
        app: nanovm-service
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: nanovm
        image: nanovm/enterprise:latest
        imagePullPolicy: Always
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
        resources:
          limits:
            cpu: "2"
            memory: "1Gi"
          requests:
            cpu: "500m"
            memory: "512Mi"
        volumeMounts:
        - name: config-volume
          mountPath: /etc/nanovm
          readOnly: true
        - name: certs-volume
          mountPath: /etc/certs
          readOnly: true
        - name: tmp-volume
          mountPath: /tmp
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8443
          name: https
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        env:
        - name: NANOVM_LOG_LEVEL
          value: "info"
        - name: NANOVM_CONFIG_PATH
          value: "/etc/nanovm/config.yaml"
        - name: EXT_API_KEY
          valueFrom:
            secretKeyRef:
              name: nanovm-secrets
              key: external-api-key
      volumes:
      - name: config-volume
        configMap:
          name: nanovm-config
      - name: certs-volume
        secret:
          secretName: nanovm-tls-certs
      - name: tmp-volume
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: nanovm-service
spec:
  selector:
    app: nanovm-service
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: https
    port: 443
    targetPort: 8443
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nanovm-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - service1.example.com
    - service2.example.com
    secretName: nanovm-tls-certs
  rules:
  - host: service1.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: nanovm-service
            port:
              number: 80
  - host: service2.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: nanovm-service
            port:
              number: 80
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: nanovm-config
data:
  config.yaml: |
    version: "1.0"
    resources:
      memory_limit_bytes: 536870912  # 512 MB
      cpu_limit: 1.0
      timeout_seconds: 300
      storage_limit_bytes: 1073741824  # 1 GB
    
    security:
      data_guard:
        enabled: true
        outbound_network:
          allow_outbound: true
          allowed_hostnames:
            - "api.example.com"
            - "storage.example.net"
          allowed_ips:
            - "192.168.1.0/24"
          allowed_ports:
            - 80
            - 443
          bandwidth_limit_bps: 1048576  # 1 MB/s
        filesystem:
          allow_filesystem: true
          storage_limit_bytes: 104857600  # 100 MB
          allowed_paths:
            - "/tmp"
          allow_writes: true
        isolation:
          strict_isolation: true
          allow_instance_data_sharing: false
          max_data_classification: 2
        auditing:
          enabled: true
          retention_days: 30
          log_all_access: false
      
      wx_policy:
        strict: true
        audit_logging: true
        default_protection: "ReadOnly"
        memory_regions: []
      
      sandbox:
        enabled: true
        allow_syscalls: false
        allowed_syscalls: []
        enable_seccomp: true
    
    network:
      urls:
        - "https://service1.example.com"
        - "https://service2.example.com"
      interface:
        enable_inbound: true
        enable_outbound: true
        listen_port: 8080
        max_connections: 1000
        connection_timeout_seconds: 30
      tls:
        enabled: true
        cert_path: "/etc/certs/tls.crt"
        key_path: "/etc/certs/tls.key"
        min_version: "1.3"
    
    scaling:
      mirrors: 2
      autoscale:
        enabled: true
        min_instances: 2
        max_instances: 5
        cpu_threshold: 75
        cooldown_seconds: 60
      state_sync:
        sync_interval_ms: 1000
        max_delta_size_bytes: 1048576  # 1 MB
        enable_conflict_resolution: true
    
    secrets:
      api_keys:
        - name: "EXTERNAL_API_KEY"
          value_from: "env:EXT_API_KEY"
      env_vars: []
    
    observability:
      metrics:
        enabled: true
        interval_seconds: 15
        exporters:
          - type_: "prometheus"
            endpoint: "/metrics"
            config: {}
      tracing:
        enabled: true
        sampling_rate: 0.1
        exporter:
          type_: "jaeger"
          endpoint: "http://jaeger-collector:14268/api/traces"
          config:
            service_name: "nanovm"
      logging:
        level: "Info"
        log_to_stdout: true
        log_to_file: false
        log_file: null
        format: "Json"

