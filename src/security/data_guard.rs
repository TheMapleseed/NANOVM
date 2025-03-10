// src/security/data_guard.rs

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use tokio::sync::mpsc;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use tracing::{debug, error, info, warn};
use thiserror::Error;

use crate::config::DataGuardConfig;

/// Configuration for the Data Guard subsystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataGuardConfig {
    /// Whether the Data Guard is enabled
    pub enabled: bool,
    
    /// Outbound network access controls
    pub outbound_network: OutboundNetworkConfig,
    
    /// Filesystem access controls
    pub filesystem: FilesystemConfig,
    
    /// Data isolation policy
    pub isolation: IsolationPolicy,
    
    /// Audit logging configuration
    pub auditing: AuditConfig,
}

/// Configuration for outbound network access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundNetworkConfig {
    /// Whether outbound connections are allowed at all
    pub allow_outbound: bool,
    
    /// List of allowed outbound hostnames/domains
    pub allowed_hostnames: Vec<String>,
    
    /// List of allowed outbound IP addresses/CIDRs
    pub allowed_ips: Vec<String>,
    
    /// List of allowed outbound ports
    pub allowed_ports: Vec<u16>,
    
    /// Maximum bandwidth limit in bytes per second (0 = unlimited)
    pub bandwidth_limit_bps: u64,
}

/// Configuration for filesystem access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemConfig {
    /// Whether filesystem access is allowed at all
    pub allow_filesystem: bool,
    
    /// Maximum storage limit in bytes
    pub storage_limit_bytes: u64,
    
    /// List of allowed filesystem paths (if any)
    pub allowed_paths: Vec<String>,
    
    /// Whether writes are allowed or read-only access
    pub allow_writes: bool,
}

/// Data isolation policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationPolicy {
    /// Whether strict isolation is enforced
    pub strict_isolation: bool,
    
    /// Whether data can be shared between VM instances
    pub allow_instance_data_sharing: bool,
    
    /// Maximum allowed data classification level (0-5)
    pub max_data_classification: u8,
}

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Whether audit logging is enabled
    pub enabled: bool,
    
    /// Retention period for audit logs in days
    pub retention_days: u32,
    
    /// Whether to log all access attempts or only violations
    pub log_all_access: bool,
}

/// Severity level for security events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityEventSeverity {
    /// Informational event
    Info,
    
    /// Warning event - potential security concern
    Warning,
    
    /// Critical security violation
    Critical,
}

/// Security event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique identifier for this event
    pub id: Uuid,
    
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    
    /// Severity level
    pub severity: SecurityEventSeverity,
    
    /// Category of security event
    pub category: String,
    
    /// Human-readable description
    pub description: String,
    
    /// Associated instance ID (if any)
    pub instance_id: Option<Uuid>,
    
    /// Additional context as key-value pairs
    pub context: HashMap<String, String>,
}

/// Core Data Guard implementation
pub struct DataGuard {
    /// Unique identifier for this DataGuard instance
    id: Uuid,
    
    /// Configuration
    config: RwLock<DataGuardConfig>,
    
    /// Set of allowed outbound destinations (host:port)
    allowed_destinations: RwLock<HashSet<String>>,
    
    /// Set of allowed outbound IP addresses
    allowed_ip_addresses: RwLock<HashSet<IpAddr>>,
    
    /// Security event channel
    event_tx: mpsc::Sender<SecurityEvent>,
    
    /// Current bandwidth tracking
    bandwidth_tracker: Arc<RwLock<BandwidthTracker>>,
    
    /// API key registry
    api_keys: RwLock<HashMap<String, ApiKeyConfig>>,
}

/// Bandwidth usage tracking
struct BandwidthTracker {
    /// Bytes sent in current time window
    bytes_sent: u64,
    
    /// Bytes received in current time window
    bytes_received: u64,
    
    /// Start time of current tracking window
    window_start: DateTime<Utc>,
    
    /// History of bandwidth usage (timestamp -> [sent, received])
    history: Vec<(DateTime<Utc>, [u64; 2])>,
    
    /// Bandwidth limit enforcement state
    throttled: bool,
}

/// Configuration for managed API keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Name/identifier for this API key
    pub name: String,
    
    /// Whether this API key is enabled
    pub enabled: bool,
    
    /// Expiration timestamp (None = never expires)
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Allowed API operations for this key (empty = all)
    pub allowed_operations: Vec<String>,
    
    /// Rate limit in requests per minute (0 = unlimited)
    pub rate_limit_rpm: u32,
}

impl DataGuard {
    /// Creates a new Data Guard instance with the provided configuration
    pub fn new(config: DataGuardConfig) -> Result<(Self, mpsc::Receiver<SecurityEvent>), DataGuardError> {
        // Create channel for security events
        let (event_tx, event_rx) = mpsc::channel(10000);
        
        // Initialize allowed destinations
        let mut allowed_destinations = HashSet::new();
        let mut allowed_ip_addresses = HashSet::new();
        
        // Process network whitelist configuration
        for hostname in &config.outbound_network.allowed_hostnames {
            for port in &config.outbound_network.allowed_ports {
                allowed_destinations.insert(format!("{}:{}", hostname, port));
            }
        }
        
        // Process IP whitelist configuration
        for ip_str in &config.outbound_network.allowed_ips {
            // Parse and validate IP addresses or CIDRs
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                allowed_ip_addresses.insert(ip);
            } else if ip_str.contains('/') {
                // Parse CIDR notation (simplified implementation)
                if let Some(slash_idx) = ip_str.find('/') {
                    let base_ip_str = &ip_str[0..slash_idx];
                    if let Ok(ip) = base_ip_str.parse::<IpAddr>() {
                        allowed_ip_addresses.insert(ip);
                        // Note: In a real implementation, we would expand the CIDR range
                    }
                }
            }
        }
        
        let guard = Self {
            id: Uuid::new_v4(),
            config: RwLock::new(config),
            allowed_destinations: RwLock::new(allowed_destinations),
            allowed_ip_addresses: RwLock::new(allowed_ip_addresses),
            event_tx,
            bandwidth_tracker: Arc::new(RwLock::new(BandwidthTracker {
                bytes_sent: 0,
                bytes_received: 0,
                window_start: Utc::now(),
                history: Vec::new(),
                throttled: false,
            })),
            api_keys: RwLock::new(HashMap::new()),
        };
        
        // Start the bandwidth monitoring task
        let bandwidth_tracker_clone = guard.bandwidth_tracker.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                Self::update_bandwidth_tracking(bandwidth_tracker_clone.clone()).await;
            }
        });
        
        Ok((guard, event_rx))
    }
    
    /// Validates an outbound network connection request
    pub async fn validate_outbound_connection(
        &self, 
        destination: &str, 
        port: u16
    ) -> Result<(), DataGuardError> {
        // Check if outbound connections are allowed at all
        if !self.config.read().unwrap().outbound_network.allow_outbound {
            self.log_security_event(
                SecurityEventSeverity::Critical,
                "network_access_violation",
                &format!("Outbound connection attempt to {}:{} blocked: outbound connections disabled", destination, port),
                None,
            ).await;
            
            return Err(DataGuardError::OutboundConnectionsDisabled);
        }
        
        // Check if the destination is in the whitelist
        let dest_port = format!("{}:{}", destination, port);
        if !self.allowed_destinations.read().unwrap().contains(&dest_port) {
            self.log_security_event(
                SecurityEventSeverity::Warning,
                "network_access_violation",
                &format!("Outbound connection attempt to non-whitelisted destination: {}", dest_port),
                None,
            ).await;
            
            return Err(DataGuardError::DestinationNotWhitelisted(dest_port));
        }
        
        // Check if we're currently throttled due to bandwidth limits
        if self.bandwidth_tracker.read().unwrap().throttled {
            self.log_security_event(
                SecurityEventSeverity::Warning,
                "bandwidth_limit_exceeded",
                &format!("Outbound connection attempt to {} throttled due to bandwidth limits", dest_port),
                None,
            ).await;
            
            return Err(DataGuardError::BandwidthLimitExceeded);
        }
        
        // Log successful validation
        if self.config.read().unwrap().auditing.log_all_access {
            self.log_security_event(
                SecurityEventSeverity::Info,
                "network_access_allowed",
                &format!("Outbound connection to {} allowed", dest_port),
                None,
            ).await;
        }
        
        Ok(())
    }
    
    /// Validates access to a filesystem path
    pub async fn validate_filesystem_access(
        &self,
        path: &str,
        write_access: bool
    ) -> Result<(), DataGuardError> {
        let config = self.config.read().unwrap();
        
        // Check if filesystem access is allowed at all
        if !config.filesystem.allow_filesystem {
            self.log_security_event(
                SecurityEventSeverity::Critical,
                "filesystem_access_violation",
                &format!("Filesystem access attempt to {} blocked: filesystem access disabled", path),
                None,
            ).await;
            
            return Err(DataGuardError::FilesystemAccessDisabled);
        }
        
        // Check write permissions if necessary
        if write_access && !config.filesystem.allow_writes {
            self.log_security_event(
                SecurityEventSeverity::Critical,
                "filesystem_write_violation",
                &format!("Write access attempt to {} blocked: filesystem is read-only", path),
                None,
            ).await;
            
            return Err(DataGuardError::FilesystemWriteDisabled);
        }
        
        // Check if the path is in the whitelist
        let path_allowed = config.filesystem.allowed_paths.iter().any(|allowed_path| {
            // Check if the path is directly allowed
            if path == allowed_path {
                return true;
            }
            
            // Check if the path is a subdirectory of an allowed path
            if allowed_path.ends_with('/') && path.starts_with(allowed_path) {
                return true;
            }
            
            false
        });
        
        if !path_allowed {
            self.log_security_event(
                SecurityEventSeverity::Warning,
                "filesystem_access_violation",
                &format!("Access attempt to non-whitelisted path: {}", path),
                None,
            ).await;
            
            return Err(DataGuardError::PathNotWhitelisted(path.to_string()));
        }
        
        // Log successful validation
        if config.auditing.log_all_access {
            self.log_security_event(
                SecurityEventSeverity::Info,
                "filesystem_access_allowed",
                &format!("Access to {} allowed (write={})", path, write_access),
                None,
            ).await;
        }
        
        Ok(())
    }
    
    /// Validates data transfer between VM instances
    pub async fn validate_instance_data_transfer(
        &self,
        source_instance_id: Uuid,
        target_instance_id: Uuid,
        data_classification: u8
    ) -> Result<(), DataGuardError> {
        let config = self.config.read().unwrap();
        
        // Check strict isolation policy
        if config.isolation.strict_isolation {
            self.log_security_event(
                SecurityEventSeverity::Critical,
                "isolation_violation",
                &format!(
                    "Data transfer attempt from instance {} to {} blocked: strict isolation enabled",
                    source_instance_id, target_instance_id
                ),
                Some(source_instance_id),
            ).await;
            
            return Err(DataGuardError::StrictIsolationEnabled);
        }
        
        // Check if instance data sharing is allowed
        if !config.isolation.allow_instance_data_sharing {
            self.log_security_event(
                SecurityEventSeverity::Critical,
                "isolation_violation",
                &format!(
                    "Data transfer attempt from instance {} to {} blocked: instance data sharing disabled",
                    source_instance_id, target_instance_id
                ),
                Some(source_instance_id),
            ).await;
            
            return Err(DataGuardError::InstanceDataSharingDisabled);
        }
        
        // Check data classification level
        if data_classification > config.isolation.max_data_classification {
            self.log_security_event(
                SecurityEventSeverity::Critical,
                "data_classification_violation",
                &format!(
                    "Data transfer attempt with classification level {} exceeds maximum allowed level {}",
                    data_classification, config.isolation.max_data_classification
                ),
                Some(source_instance_id),
            ).await;
            
            return Err(DataGuardError::DataClassificationExceedsLimit {
                actual: data_classification,
                maximum: config.isolation.max_data_classification,
            });
        }
        
        // Log successful validation
        if config.auditing.log_all_access {
            self.log_security_event(
                SecurityEventSeverity::Info,
                "instance_data_transfer_allowed",
                &format!(
                    "Data transfer from instance {} to {} allowed (classification={})",
                    source_instance_id, target_instance_id, data_classification
                ),
                Some(source_instance_id),
            ).await;
        }
        
        Ok(())
    }
    
    /// Registers an API key with the Data Guard
    pub fn register_api_key(&self, key_config: ApiKeyConfig) -> Result<(), DataGuardError> {
        let mut api_keys = self.api_keys.write().unwrap();
        
        if api_keys.contains_key(&key_config.name) {
            return Err(DataGuardError::ApiKeyAlreadyExists(key_config.name));
        }
        
        api_keys.insert(key_config.name.clone(), key_config);
        
        Ok(())
    }
    
    /// Validates an API key for a specific operation
    pub async fn validate_api_key(&self, key_name: &str, operation: &str) -> Result<(), DataGuardError> {
        let api_keys = self.api_keys.read().unwrap();
        
        let key_config = api_keys.get(key_name)
            .ok_or_else(|| DataGuardError::ApiKeyNotFound(key_name.to_string()))?;
            
        // Check if the key is enabled
        if !key_config.enabled {
            self.log_security_event(
                SecurityEventSeverity::Warning,
                "api_key_validation_failure",
                &format!("API key {} is disabled", key_name),
                None,
            ).await;
            
            return Err(DataGuardError::ApiKeyDisabled(key_name.to_string()));
        }
        
        // Check if the key has expired
        if let Some(expires_at) = key_config.expires_at {
            if expires_at < Utc::now() {
                self.log_security_event(
                    SecurityEventSeverity::Warning,
                    "api_key_validation_failure",
                    &format!("API key {} has expired", key_name),
                    None,
                ).await;
                
                return Err(DataGuardError::ApiKeyExpired {
                    key: key_name.to_string(),
                    expired_at: expires_at,
                });
            }
        }
        
        // Check if the operation is allowed
        if !key_config.allowed_operations.is_empty() && !key_config.allowed_operations.contains(&operation.to_string()) {
            self.log_security_event(
                SecurityEventSeverity::Warning,
                "api_key_validation_failure",
                &format!("Operation {} not allowed for API key {}", operation, key_name),
                None,
            ).await;
            
            return Err(DataGuardError::OperationNotAllowed {
                key: key_name.to_string(),
                operation: operation.to_string(),
            });
        }
        
        // Log successful validation
        if self.config.read().unwrap().auditing.log_all_access {
            self.log_security_event(
                SecurityEventSeverity::Info,
                "api_key_validation_success",
                &format!("API key {} validated for operation {}", key_name, operation),
                None,
            ).await;
        }
        
        Ok(())
    }
    
    /// Records network traffic for bandwidth tracking
    pub async fn record_network_traffic(&self, bytes_sent: u64, bytes_received: u64) {
        let mut tracker = self.bandwidth_tracker.write().unwrap();
        tracker.bytes_sent += bytes_sent;
        tracker.bytes_received += bytes_received;
        
        // Check if we've exceeded the bandwidth limit
        let limit = self.config.read().unwrap().outbound_network.bandwidth_limit_bps;
        if limit > 0 {
            // Calculate rate over the last second
            let elapsed = (Utc::now() - tracker.window_start).num_milliseconds() as f64 / 1000.0;
            if elapsed > 0.0 {
                let bytes_per_second = tracker.bytes_sent as f64 / elapsed;
                if bytes_per_second > limit as f64 {
                    tracker.throttled = true;
                    
                    // Log the bandwidth limit violation
                    drop(tracker); // Release the lock before async operation
                    self.log_security_event(
                        SecurityEventSeverity::Warning,
                        "bandwidth_limit_exceeded",
                        &format!(
                            "Bandwidth limit exceeded: {:.2} bytes/sec (limit: {} bytes/sec)",
                            bytes_per_second, limit
                        ),
                        None,
                    ).await;
                }
            }
        }
    }
    
    /// Updates the bandwidth tracking
    async fn update_bandwidth_tracking(tracker: Arc<RwLock<BandwidthTracker>>) {
        let mut tracker_lock = tracker.write().unwrap();
        let now = Utc::now();
        
        // Record the current window data
        tracker_lock.history.push((
            tracker_lock.window_start,
            [tracker_lock.bytes_sent, tracker_lock.bytes_received],
        ));
        
        // Trim history (keep last 60 seconds)
        let one_minute_ago = now - chrono::Duration::seconds(60);
        tracker_lock.history.retain(|(timestamp, _)| *timestamp >= one_minute_ago);
        
        // Reset for new window
        tracker_lock.bytes_sent = 0;
        tracker_lock.bytes_received = 0;
        tracker_lock.window_start = now;
        
        // Reset throttling state if appropriate
        tracker_lock.throttled = false;
    }
    
    /// Logs a security event
    async fn log_security_event(
        &self,
        severity: SecurityEventSeverity,
        category: &str,
        description: &str,
        instance_id: Option<Uuid>,
    ) {
        let event = SecurityEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category: category.to_string(),
            description: description.to_string(),
            instance_id,
            context: HashMap::new(),
        };
        
        // Log the event to the security event channel
        if let Err(e) = self.event_tx.send(event.clone()).await {
            error!("Failed to send security event: {}", e);
        }
        
        // Log to tracing based on severity
        match severity {
            SecurityEventSeverity::Info => {
                info!(
                    event_id = %event.id,
                    category = %category,
                    instance_id = ?instance_id,
                    "SECURITY: {}",
                    description
                );
            }
            SecurityEventSeverity::Warning => {
                warn!(
                    event_id = %event.id,
                    category = %category,
                    instance_id = ?instance_id,
                    "SECURITY WARNING: {}",
                    description
                );
            }
            SecurityEventSeverity::Critical => {
                error!(
                    event_id = %event.id,
                    category = %category,
                    instance_id = ?instance_id,
                    "SECURITY CRITICAL: {}",
                    description
                );
            }
        }
    }
}

/// Errors that can occur during Data Guard operations
#[derive(Error, Debug)]
pub enum DataGuardError {
    #[error("Outbound connections are disabled")]
    OutboundConnectionsDisabled,
    
    #[error("Destination not in whitelist: {0}")]
    DestinationNotWhitelisted(String),
    
    #[error("Bandwidth limit exceeded")]
    BandwidthLimitExceeded,
    
    #[error("Filesystem access is disabled")]
    FilesystemAccessDisabled,
    
    #[error("Filesystem write access is disabled")]
    FilesystemWriteDisabled,
    
    #[error("Path not in whitelist: {0}")]
    PathNotWhitelisted(String),
    
    #[error("Strict isolation policy is enabled")]
    StrictIsolationEnabled,
    
    #[error("Instance data sharing is disabled")]
    InstanceDataSharingDisabled,
    
    #[error("Data classification {actual} exceeds maximum allowed level {maximum}")]
    DataClassificationExceedsLimit {
        actual: u8,
        maximum: u8,
    },
    
    #[error("API key not found: {0}")]
    ApiKeyNotFound(String),
    
    #[error("API key is disabled: {0}")]
    ApiKeyDisabled(String),
    
    #[error("API key has expired: {key} (expired at {expired_at})")]
    ApiKeyExpired {
        key: String,
        expired_at: DateTime<Utc>,
    },
    
    #[error("Operation not allowed: {operation} (key: {key})")]
    OperationNotAllowed {
        key: String,
        operation: String,
    },
    
    #[error("API key already exists: {0}")]
    ApiKeyAlreadyExists(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}