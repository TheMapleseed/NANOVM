// src/security/api_keys.rs

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use chrono::{DateTime, Duration, Utc};
use ring::hmac;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::security::data_guard::DataGuard;

/// Maximum number of rate-limited requests per key
const MAX_RATE_LIMITED_REQUESTS: usize = 10_000;

/// API key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiKeyType {
    /// Master key with full access
    Master,
    
    /// Admin key with administrative access
    Admin,
    
    /// User key with limited access
    User,
    
    /// Service key for service-to-service communication
    Service,
    
    /// Temporary key with short lifespan
    Temporary,
}

/// API key scope
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiKeyScope {
    /// Full access to all operations
    FullAccess,
    
    /// Read-only access
    ReadOnly,
    
    /// Write-only access
    WriteOnly,
    
    /// Access to a specific resource
    Resource(String),
    
    /// Access to a specific action
    Action(String),
    
    /// Access to a specific instance
    Instance(Uuid),
}

/// API key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Unique identifier for this API key
    pub id: Uuid,
    
    /// Human-readable name for this API key
    pub name: String,
    
    /// API key type
    pub key_type: ApiKeyType,
    
    /// API key scopes
    pub scopes: HashSet<ApiKeyScope>,
    
    /// Expiration date (None = never expires)
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Rate limit in requests per minute (0 = unlimited)
    pub rate_limit_rpm: u32,
    
    /// Associated instance ID (if any)
    pub instance_id: Option<Uuid>,
    
    /// Creation time
    pub created_at: DateTime<Utc>,
    
    /// Last used time
    pub last_used_at: Option<DateTime<Utc>>,
    
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// API key state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyState {
    /// API key is active
    Active,
    
    /// API key is disabled
    Disabled,
    
    /// API key is expired
    Expired,
    
    /// API key is revoked
    Revoked,
}

/// API key with sensitive information
#[derive(Debug, Clone)]
pub struct ApiKey {
    /// API key configuration
    pub config: ApiKeyConfig,
    
    /// API key state
    pub state: ApiKeyState,
    
    /// API key hash
    key_hash: String,
    
    /// API key prefix (first few characters)
    key_prefix: String,
}

/// API key validation result
#[derive(Debug, Clone)]
pub struct ApiKeyValidationResult {
    /// Whether the API key is valid
    pub valid: bool,
    
    /// API key configuration (if valid)
    pub config: Option<ApiKeyConfig>,
    
    /// Validation error (if any)
    pub error: Option<ApiKeyValidationError>,
}

/// API key validation error
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiKeyValidationError {
    /// API key not found
    NotFound,
    
    /// API key expired
    Expired,
    
    /// API key disabled
    Disabled,
    
    /// API key revoked
    Revoked,
    
    /// API key scope mismatch
    ScopeMismatch,
    
    /// API key rate limited
    RateLimited,
    
    /// API key instance mismatch
    InstanceMismatch,
}

/// Rate limit tracking for an API key
#[derive(Debug, Clone)]
struct RateLimitTracker {
    /// API key ID
    key_id: Uuid,
    
    /// Request timestamps within the current window
    request_timestamps: Vec<DateTime<Utc>>,
    
    /// Rate limit in requests per minute
    rate_limit_rpm: u32,
}

/// API key manager for securely managing API keys
pub struct ApiKeyManager {
    /// Unique identifier for this manager
    id: Uuid,
    
    /// API keys by ID
    keys_by_id: RwLock<HashMap<Uuid, ApiKey>>,
    
    /// API keys by prefix
    keys_by_prefix: RwLock<HashMap<String, Uuid>>,
    
    /// Rate limit trackers by key ID
    rate_limiters: RwLock<HashMap<Uuid, RateLimitTracker>>,
    
    /// Data Guard for security validation
    data_guard: Arc<DataGuard>,
    
    /// Signing key for generating new API keys
    signing_key: hmac::Key,
}

impl ApiKeyManager {
    /// Creates a new API key manager
    pub fn new(data_guard: Arc<DataGuard>, signing_key: &[u8]) -> Self {
        // Create HMAC key
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, signing_key);
        
        Self {
            id: Uuid::new_v4(),
            keys_by_id: RwLock::new(HashMap::new()),
            keys_by_prefix: RwLock::new(HashMap::new()),
            rate_limiters: RwLock::new(HashMap::new()),
            data_guard,
            signing_key: hmac_key,
        }
    }
    
    /// Creates a new API key
    pub fn create_key(&self, config: ApiKeyConfig) -> Result<String, ApiKeyError> {
        // Check if key with this ID already exists
        {
            let keys = self.keys_by_id.read().unwrap();
            if keys.contains_key(&config.id) {
                return Err(ApiKeyError::DuplicateId);
            }
        }
        
        // Generate a new API key
        let key_bytes = generate_random_bytes(32)?;
        let key_string = encode_key(&key_bytes);
        
        // Get key prefix (first 8 characters)
        let key_prefix = key_string[0..8].to_string();
        
        // Hash the key for storage
        let key_hash = hash_key(&key_string);
        
        // Create API key
        let api_key = ApiKey {
            config,
            state: ApiKeyState::Active,
            key_hash,
            key_prefix: key_prefix.clone(),
        };
        
        // Store the key
        {
            let mut keys_by_id = self.keys_by_id.write().unwrap();
            let mut keys_by_prefix = self.keys_by_prefix.write().unwrap();
            
            // Check if prefix already exists
            if keys_by_prefix.contains_key(&key_prefix) {
                return Err(ApiKeyError::DuplicatePrefix);
            }
            
            keys_by_id.insert(api_key.config.id, api_key.clone());
            keys_by_prefix.insert(key_prefix, api_key.config.id);
        }
        
        // Create rate limiter if needed
        if api_key.config.rate_limit_rpm > 0 {
            let mut rate_limiters = self.rate_limiters.write().unwrap();
            rate_limiters.insert(api_key.config.id, RateLimitTracker {
                key_id: api_key.config.id,
                request_timestamps: Vec::with_capacity(api_key.config.rate_limit_rpm as usize),
                rate_limit_rpm: api_key.config.rate_limit_rpm,
            });
        }
        
        info!("Created new API key: {} ({})", api_key.config.name, api_key.config.id);
        
        Ok(key_string)
    }
    
    /// Validates an API key
    pub async fn validate_key(
        &self,
        key: &str,
        scopes: &[ApiKeyScope],
        instance_id: Option<Uuid>,
    ) -> ApiKeyValidationResult {
        // Get key prefix
        let key_prefix = if key.len() >= 8 {
            key[0..8].to_string()
        } else {
            return ApiKeyValidationResult {
                valid: false,
                config: None,
                error: Some(ApiKeyValidationError::NotFound),
            };
        };
        
        // Look up key by prefix
        let key_id = {
            let keys_by_prefix = self.keys_by_prefix.read().unwrap();
            match keys_by_prefix.get(&key_prefix) {
                Some(id) => *id,
                None => {
                    return ApiKeyValidationResult {
                        valid: false,
                        config: None,
                        error: Some(ApiKeyValidationError::NotFound),
                    };
                }
            }
        };
        
        // Get API key
        let api_key = {
            let keys_by_id = self.keys_by_id.read().unwrap();
            match keys_by_id.get(&key_id) {
                Some(api_key) => api_key.clone(),
                None => {
                    return ApiKeyValidationResult {
                        valid: false,
                        config: None,
                        error: Some(ApiKeyValidationError::NotFound),
                    };
                }
            }
        };
        
        // Verify key hash
        let key_hash = hash_key(key);
        if key_hash != api_key.key_hash {
            return ApiKeyValidationResult {
                valid: false,
                config: None,
                error: Some(ApiKeyValidationError::NotFound),
            };
        }
        
        // Check key state
        match api_key.state {
            ApiKeyState::Active => {
                // Check expiration
                if let Some(expires_at) = api_key.config.expires_at {
                    if expires_at < Utc::now() {
                        // Update key state
                        self.update_key_state(api_key.config.id, ApiKeyState::Expired);
                        
                        return ApiKeyValidationResult {
                            valid: false,
                            config: Some(api_key.config),
                            error: Some(ApiKeyValidationError::Expired),
                        };
                    }
                }
                
                // Check instance ID
                if let Some(required_instance_id) = api_key.config.instance_id {
                    if instance_id != Some(required_instance_id) {
                        return ApiKeyValidationResult {
                            valid: false,
                            config: Some(api_key.config),
                            error: Some(ApiKeyValidationError::InstanceMismatch),
                        };
                    }
                }
                
                // Check scopes
                let has_full_access = api_key.config.scopes.contains(&ApiKeyScope::FullAccess);
                
                if !has_full_access {
                    // Check if all required scopes are present
                    let has_all_scopes = scopes.iter().all(|scope| {
                        api_key.config.scopes.contains(scope)
                    });
                    
                    if !has_all_scopes {
                        return ApiKeyValidationResult {
                            valid: false,
                            config: Some(api_key.config),
                            error: Some(ApiKeyValidationError::ScopeMismatch),
                        };
                    }
                }
                
                // Check rate limit
                if api_key.config.rate_limit_rpm > 0 {
                    let is_rate_limited = self.check_rate_limit(api_key.config.id)?;
                    
                    if is_rate_limited {
                        return ApiKeyValidationResult {
                            valid: false,
                            config: Some(api_key.config),
                            error: Some(ApiKeyValidationError::RateLimited),
                        };
                    }
                }
                
                // Update last used time
                self.update_last_used(api_key.config.id);
                
                // Record request for rate limiting
                if api_key.config.rate_limit_rpm > 0 {
                    self.record_request(api_key.config.id)?;
                }
                
                // Validate with Data Guard
                if let Err(e) = self.data_guard.validate_api_key(&api_key.config.name, "validate_key").await {
                    warn!("Data Guard rejected API key: {}", e);
                    
                    // Map error to validation error
                    let validation_error = match e {
                        crate::security::data_guard::DataGuardError::ApiKeyDisabled(_) => {
                            ApiKeyValidationError::Disabled
                        }
                        crate::security::data_guard::DataGuardError::ApiKeyExpired { .. } => {
                            ApiKeyValidationError::Expired
                        }
                        crate::security::data_guard::DataGuardError::OperationNotAllowed { .. } => {
                            ApiKeyValidationError::ScopeMismatch
                        }
                        _ => {
                            ApiKeyValidationError::NotFound
                        }
                    };
                    
                    return ApiKeyValidationResult {
                        valid: false,
                        config: Some(api_key.config),
                        error: Some(validation_error),
                    };
                }
                
                // Key is valid
                ApiKeyValidationResult {
                    valid: true,
                    config: Some(api_key.config),
                    error: None,
                }
            }
            ApiKeyState::Disabled => {
                ApiKeyValidationResult {
                    valid: false,
                    config: Some(api_key.config),
                    error: Some(ApiKeyValidationError::Disabled),
                }
            }
            ApiKeyState::Expired => {
                ApiKeyValidationResult {
                    valid: false,
                    config: Some(api_key.config),
                    error: Some(ApiKeyValidationError::Expired),
                }
            }
            ApiKeyState::Revoked => {
                ApiKeyValidationResult {
                    valid: false,
                    config: Some(api_key.config),
                    error: Some(ApiKeyValidationError::Revoked),
                }
            }
        }
    }
    
    /// Revokes an API key
    pub fn revoke_key(&self, key_id: Uuid) -> Result<(), ApiKeyError> {
        // Update key state to revoked
        self.update_key_state(key_id, ApiKeyState::Revoked)?;
        
        // Log revocation event with appropriate context for audit trails
        info!("API key {} has been revoked", key_id);
        
        // Remove from rate limiter map to free resources
        {
            let mut rate_limiters = self.rate_limiters.write().unwrap();
            rate_limiters.remove(&key_id);
        }
        
        Ok(())
    }
    
    /// Disables an API key (temporary revocation)
    pub fn disable_key(&self, key_id: Uuid) -> Result<(), ApiKeyError> {
        // Update key state to disabled
        self.update_key_state(key_id, ApiKeyState::Disabled)?;
        
        info!("API key {} has been disabled", key_id);
        
        Ok(())
    }
    
    /// Re-enables a disabled API key
    pub fn enable_key(&self, key_id: Uuid) -> Result<(), ApiKeyError> {
        // Get current key state
        let current_state = {
            let keys = self.keys_by_id.read().unwrap();
            match keys.get(&key_id) {
                Some(api_key) => api_key.state,
                None => return Err(ApiKeyError::KeyNotFound),
            }
        };
        
        // Only enable if currently disabled
        if current_state != ApiKeyState::Disabled {
            return Err(ApiKeyError::InvalidStateTransition {
                current: current_state,
                target: ApiKeyState::Active,
            });
        }
        
        // Update key state to active
        self.update_key_state(key_id, ApiKeyState::Active)?;
        
        info!("API key {} has been re-enabled", key_id);
        
        Ok(())
    }
    
    /// Updates the state of an API key
    fn update_key_state(&self, key_id: Uuid, new_state: ApiKeyState) -> Result<(), ApiKeyError> {
        let mut keys = self.keys_by_id.write().unwrap();
        
        if let Some(api_key) = keys.get_mut(&key_id) {
            // Validate state transition
            match (api_key.state, new_state) {
                // Cannot transition from revoked to any other state
                (ApiKeyState::Revoked, _) => {
                    return Err(ApiKeyError::InvalidStateTransition {
                        current: ApiKeyState::Revoked,
                        target: new_state,
                    });
                }
                // All other transitions are allowed
                _ => {
                    api_key.state = new_state;
                }
            }
            
            Ok(())
        } else {
            Err(ApiKeyError::KeyNotFound)
        }
    }
    
    /// Updates the last used timestamp for an API key
    fn update_last_used(&self, key_id: Uuid) {
        let mut keys = self.keys_by_id.write().unwrap();
        
        if let Some(api_key) = keys.get_mut(&key_id) {
            api_key.config.last_used_at = Some(Utc::now());
        }
    }
    
    /// Checks if an API key is rate limited
    fn check_rate_limit(&self, key_id: Uuid) -> Result<bool, ApiKeyError> {
        let rate_limiters = self.rate_limiters.read().unwrap();
        
        if let Some(rate_limiter) = rate_limiters.get(&key_id) {
            // Calculate the rate limit window (1 minute)
            let window_start = Utc::now() - Duration::minutes(1);
            
            // Count requests within the window
            let requests_in_window = rate_limiter.request_timestamps.iter()
                .filter(|timestamp| **timestamp >= window_start)
                .count();
            
            // Check if rate limit is exceeded
            Ok(requests_in_window >= rate_limiter.rate_limit_rpm as usize)
        } else {
            // No rate limiter found, not rate limited
            Ok(false)
        }
    }
    
    /// Records a request for rate limiting
    fn record_request(&self, key_id: Uuid) -> Result<(), ApiKeyError> {
        let mut rate_limiters = self.rate_limiters.write().unwrap();
        
        if let Some(rate_limiter) = rate_limiters.get_mut(&key_id) {
            // Add current timestamp
            rate_limiter.request_timestamps.push(Utc::now());
            
            // Keep only the most recent timestamps within the window
            // This prevents unbounded memory growth
            if rate_limiter.request_timestamps.len() > MAX_RATE_LIMITED_REQUESTS {
                // Sort by timestamp (oldest first)
                rate_limiter.request_timestamps.sort();
                
                // Calculate the rate limit window (1 minute)
                let window_start = Utc::now() - Duration::minutes(1);
                
                // Find the index of the first timestamp within the window
                if let Some(index) = rate_limiter.request_timestamps.iter()
                    .position(|timestamp| *timestamp >= window_start) {
                    
                    // Remove all timestamps before the window
                    rate_limiter.request_timestamps = rate_limiter.request_timestamps.split_off(index);
                }
            }
            
            Ok(())
        } else {
            Err(ApiKeyError::KeyNotFound)
        }
    }
    
    /// Gets information about an API key by ID
    pub fn get_key_by_id(&self, key_id: Uuid) -> Result<ApiKeyConfig, ApiKeyError> {
        let keys = self.keys_by_id.read().unwrap();
        
        if let Some(api_key) = keys.get(&key_id) {
            Ok(api_key.config.clone())
        } else {
            Err(ApiKeyError::KeyNotFound)
        }
    }
    
    /// Lists all API keys
    pub fn list_keys(&self) -> Vec<ApiKeyConfig> {
        let keys = self.keys_by_id.read().unwrap();
        
        keys.values()
            .map(|api_key| api_key.config.clone())
            .collect()
    }
    
    /// Rotates an API key (revokes the old key and creates a new one)
    pub fn rotate_key(&self, key_id: Uuid) -> Result<String, ApiKeyError> {
        // Get the current key config
        let config = {
            let keys = self.keys_by_id.read().unwrap();
            match keys.get(&key_id) {
                Some(api_key) => api_key.config.clone(),
                None => return Err(ApiKeyError::KeyNotFound),
            }
        };
        
        // Create a new key config
        let new_config = ApiKeyConfig {
            id: Uuid::new_v4(),
            name: format!("{} (rotated)", config.name),
            key_type: config.key_type,
            scopes: config.scopes.clone(),
            expires_at: config.expires_at,
            rate_limit_rpm: config.rate_limit_rpm,
            instance_id: config.instance_id,
            created_at: Utc::now(),
            last_used_at: None,
            metadata: config.metadata.clone(),
        };
        
        // Create the new key
        let new_key = self.create_key(new_config)?;
        
        // Revoke the old key
        self.revoke_key(key_id)?;
        
        Ok(new_key)
    }
    
    /// Updates the expiration time of an API key
    pub fn update_expiration(&self, key_id: Uuid, expires_at: Option<DateTime<Utc>>) -> Result<(), ApiKeyError> {
        let mut keys = self.keys_by_id.write().unwrap();
        
        if let Some(api_key) = keys.get_mut(&key_id) {
            api_key.config.expires_at = expires_at;
            Ok(())
        } else {
            Err(ApiKeyError::KeyNotFound)
        }
    }
    
    /// Updates the rate limit of an API key
    pub fn update_rate_limit(&self, key_id: Uuid, rate_limit_rpm: u32) -> Result<(), ApiKeyError> {
        // Update the key config
        {
            let mut keys = self.keys_by_id.write().unwrap();
            
            if let Some(api_key) = keys.get_mut(&key_id) {
                api_key.config.rate_limit_rpm = rate_limit_rpm;
            } else {
                return Err(ApiKeyError::KeyNotFound);
            }
        }
        
        // Update the rate limiter
        {
            let mut rate_limiters = self.rate_limiters.write().unwrap();
            
            if rate_limit_rpm > 0 {
                // Create or update rate limiter
                rate_limiters.entry(key_id)
                    .and_modify(|limiter| limiter.rate_limit_rpm = rate_limit_rpm)
                    .or_insert_with(|| RateLimitTracker {
                        key_id,
                        request_timestamps: Vec::with_capacity(rate_limit_rpm as usize),
                        rate_limit_rpm,
                    });
            } else {
                // Remove rate limiter if rate limit is disabled
                rate_limiters.remove(&key_id);
            }
        }
        
        Ok(())
    }
    
    /// Updates the scopes of an API key
    pub fn update_scopes(&self, key_id: Uuid, scopes: HashSet<ApiKeyScope>) -> Result<(), ApiKeyError> {
        let mut keys = self.keys_by_id.write().unwrap();
        
        if let Some(api_key) = keys.get_mut(&key_id) {
            api_key.config.scopes = scopes;
            Ok(())
        } else {
            Err(ApiKeyError::KeyNotFound)
        }
    }
    
    /// Finds all API keys for an instance
    pub fn find_keys_for_instance(&self, instance_id: Uuid) -> Vec<ApiKeyConfig> {
        let keys = self.keys_by_id.read().unwrap();
        
        keys.values()
            .filter(|api_key| api_key.config.instance_id == Some(instance_id))
            .map(|api_key| api_key.config.clone())
            .collect()
    }
    
    /// Purges expired API keys
    pub fn purge_expired_keys(&self) -> usize {
        let now = Utc::now();
        let mut purged_count = 0;
        
        // Find expired keys
        let expired_keys: Vec<Uuid> = {
            let keys = self.keys_by_id.read().unwrap();
            
            keys.values()
                .filter(|api_key| {
                    if let Some(expires_at) = api_key.config.expires_at {
                        expires_at < now
                    } else {
                        false
                    }
                })
                .map(|api_key| api_key.config.id)
                .collect()
        };
        
        // Update state for expired keys
        for key_id in &expired_keys {
            if let Ok(()) = self.update_key_state(*key_id, ApiKeyState::Expired) {
                purged_count += 1;
            }
        }
        
        // Remove expired keys from rate limiters
        {
            let mut rate_limiters = self.rate_limiters.write().unwrap();
            
            for key_id in &expired_keys {
                rate_limiters.remove(key_id);
            }
        }
        
        purged_count
    }
}

/// Generates random bytes for key creation
fn generate_random_bytes(length: usize) -> Result<Vec<u8>, ApiKeyError> {
    let mut bytes = vec![0u8; length];
    
    // Use a cryptographically secure RNG
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ApiKeyError::KeyGenerationFailed)?;
    
    Ok(bytes)
}

/// Encodes bytes as a base64 string for key representation
fn encode_key(bytes: &[u8]) -> String {
    // Use URL-safe base64 without padding
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

/// Hashes a key for secure storage
fn hash_key(key: &str) -> String {
    use ring::digest;
    
    // Use SHA-256 for hashing
    let digest = digest::digest(&digest::SHA256, key.as_bytes());
    
    // Convert to hexadecimal string
    hex::encode(digest.as_ref())
}

/// Error during API key operations
#[derive(Debug, thiserror::Error)]
pub enum ApiKeyError {
    #[error("API key not found")]
    KeyNotFound,
    
    #[error("Duplicate API key ID")]
    DuplicateId,
    
    #[error("Duplicate API key prefix")]
    DuplicatePrefix,
    
    #[error("API key generation failed")]
    KeyGenerationFailed,
    
    #[error("Invalid state transition from {current:?} to {target:?}")]
    InvalidStateTransition {
        current: ApiKeyState,
        target: ApiKeyState,
    },
    
    #[error("Invalid API key")]
    InvalidKey,
    
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
}