use std::path::{Path, PathBuf};
use std::fs;
use crate::config::{ConfigError, VmConfig, TlsVersion, NetworkConfig, SecurityConfig};

/// Configuration validator
pub struct ConfigValidator {
    // Add internal state as needed
}

impl ConfigValidator {
    /// Creates a new configuration validator
    pub fn new() -> Self {
        Self {}
    }
    
    /// Validates a configuration
    pub fn validate(&self, config: &VmConfig) -> Result<(), ConfigError> {
        // Validate base configuration
        if config.version.is_empty() {
            return Err(ConfigError::ValidationError(
                "Configuration version cannot be empty".to_string(),
            ));
        }
        
        // Validate resource configuration
        self.validate_resources(&config.resources)?;
        
        // Validate security configuration
        self.validate_security(&config.security)?;
        
        // Validate network configuration
        self.validate_network(&config.network)?;
        
        // Validate scaling configuration
        self.validate_scaling(&config.scaling)?;
        
        // Validate secrets configuration
        self.validate_secrets(&config.secrets)?;
        
        // Validate observability configuration
        self.validate_observability(&config.observability)?;
        
        Ok(())
    }
    
    /// Validates resource configuration
    fn validate_resources(&self, resources: &crate::config::ResourceConfig) -> Result<(), ConfigError> {
        // Validate memory limit
        if resources.memory_limit_bytes == 0 {
            return Err(ConfigError::ValidationError(
                "Memory limit cannot be zero".to_string(),
            ));
        }
        
        // Validate CPU limit
        if resources.cpu_limit <= 0.0 {
            return Err(ConfigError::ValidationError(
                "CPU limit must be positive".to_string(),
            ));
        }
        
        // Validate storage limit
        if resources.storage_limit_bytes == 0 {
            return Err(ConfigError::ValidationError(
                "Storage limit cannot be zero".to_string(),
            ));
        }
        
        Ok(())
    }
    
    /// Validates security configuration
    fn validate_security(&self, security: &SecurityConfig) -> Result<(), ConfigError> {
        // Validate W^X policy configuration
        if let Some(regions) = &security.wx_policy.memory_regions {
            for region in regions {
                if region.size_bytes == 0 {
                    return Err(ConfigError::ValidationError(
                        "Memory region size cannot be zero".to_string(),
                    ));
                }
            }
        }
        
        // Validate sandbox configuration
        if security.sandbox.enabled && security.sandbox.allow_syscalls {
            // If syscalls are allowed, ensure there's an allowlist
            if security.sandbox.allowed_syscalls.is_empty() {
                return Err(ConfigError::ValidationError(
                    "Allowed syscalls list cannot be empty when syscalls are allowed".to_string(),
                ));
            }
        }
        
        Ok(())
    }
    
    /// Safely canonicalizes a path and checks for path traversal attempts
    fn validate_path(&self, path: &str) -> Result<PathBuf, ConfigError> {
        // Check for common path traversal patterns
        if path.contains("..") || path.contains("//") || path.contains("\\\\") {
            return Err(ConfigError::ValidationError(
                format!("Potential path traversal attack detected in path: {}", path)
            ));
        }
        
        // Attempt to canonicalize the path
        let canonical_path = fs::canonicalize(path).map_err(|e| {
            ConfigError::ValidationError(
                format!("Invalid path {}: {}", path, e)
            )
        })?;
        
        // Check if the path exists
        if !canonical_path.exists() {
            return Err(ConfigError::ValidationError(
                format!("Path does not exist: {}", path)
            ));
        }
        
        Ok(canonical_path)
    }
    
    /// Validates network configuration
    fn validate_network(&self, network: &NetworkConfig) -> Result<(), ConfigError> {
        // Validate URLs - require HTTPS only
        for url in &network.urls {
            if !url.starts_with("https://") {
                return Err(ConfigError::ValidationError(
                    format!("Invalid URL: {}. Only HTTPS URLs are allowed for security.", url)
                ));
            }
        }
        
        // Validate network interface configuration
        if network.interface.max_connections == 0 {
            return Err(ConfigError::ValidationError(
                "Maximum connections cannot be zero".to_string()
            ));
        }
        
        // TLS must be enabled
        if !network.tls.enabled {
            return Err(ConfigError::ValidationError(
                "TLS must be enabled for secure operation.".to_string()
            ));
        }
        
        // Validate TLS configuration
        if network.tls.enabled {
            // Check for certificate and key paths
            if network.tls.cert_path.is_none() {
                return Err(ConfigError::ValidationError(
                    "Certificate path is required when TLS is enabled".to_string()
                ));
            }
            
            if network.tls.key_path.is_none() {
                return Err(ConfigError::ValidationError(
                    "Private key path is required when TLS is enabled".to_string()
                ));
            }
            
            // Verify certificate file exists and is safe
            if let Some(cert_path) = &network.tls.cert_path {
                self.validate_path(cert_path)?;
            }
            
            // Verify key file exists and is safe
            if let Some(key_path) = &network.tls.key_path {
                self.validate_path(key_path)?;
            }
            
            // For enterprise security, mTLS should be enabled
            if !network.tls.enable_mtls {
                return Err(ConfigError::ValidationError(
                    "mTLS must be enabled for enterprise-grade security".to_string()
                ));
            }
            
            // Validate mTLS configuration
            if network.tls.enable_mtls {
                // Client CA path is required for mTLS
                if network.tls.client_ca_path.is_none() {
                    return Err(ConfigError::ValidationError(
                        "Client CA certificate path is required when mTLS is enabled".to_string()
                    ));
                }
                
                // Verify client CA file exists and is safe
                if let Some(ca_path) = &network.tls.client_ca_path {
                    self.validate_path(ca_path)?;
                }
            }
            
            // OCSP stapling should be enabled for enhanced security
            if !network.tls.enable_ocsp_stapling {
                return Err(ConfigError::ValidationError(
                    "OCSP stapling should be enabled for certificate revocation checking".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// Validates scaling configuration
    fn validate_scaling(&self, scaling: &crate::config::ScalingConfig) -> Result<(), ConfigError> {
        // Validate autoscaling configuration
        if scaling.autoscale.enabled {
            if scaling.autoscale.min_instances == 0 {
                return Err(ConfigError::ValidationError(
                    "Minimum instances cannot be zero".to_string(),
                ));
            }
            
            if scaling.autoscale.min_instances > scaling.autoscale.max_instances {
                return Err(ConfigError::ValidationError(
                    "Minimum instances cannot be greater than maximum instances".to_string(),
                ));
            }
            
            if scaling.autoscale.cpu_threshold == 0 || scaling.autoscale.cpu_threshold > 100 {
                return Err(ConfigError::ValidationError(
                    "CPU threshold must be between 1 and 100".to_string(),
                ));
            }
        }
        
        // Validate state sync configuration
        if scaling.state_sync.sync_interval_ms == 0 {
            return Err(ConfigError::ValidationError(
                "State sync interval cannot be zero".to_string(),
            ));
        }
        
        Ok(())
    }
    
    /// Validates secrets configuration
    fn validate_secrets(&self, _secrets: &crate::config::SecretsConfig) -> Result<(), ConfigError> {
        // No specific validations needed yet
        Ok(())
    }
    
    /// Validates observability configuration
    fn validate_observability(&self, observability: &crate::config::ObservabilityConfig) -> Result<(), ConfigError> {
        // Validate metrics configuration
        if observability.metrics.enabled && observability.metrics.interval_seconds == 0 {
            return Err(ConfigError::ValidationError(
                "Metrics interval cannot be zero".to_string(),
            ));
        }
        
        // Validate tracing configuration
        if observability.tracing.enabled {
            if observability.tracing.sampling_rate < 0.0 || observability.tracing.sampling_rate > 1.0 {
                return Err(ConfigError::ValidationError(
                    "Tracing sampling rate must be between 0.0 and 1.0".to_string(),
                ));
            }
        }
        
        Ok(())
    }
} 