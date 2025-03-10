use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use url::Url;
use uuid::Uuid;

use crate::config::TlsConfig;
use crate::config::TlsVersion;
use crate::vm::instance::VmHandle;

/// URL resolver for routing network requests to VM instances
pub struct UrlResolver {
    /// Mapping of URLs to VM instance IDs
    url_to_instance: RwLock<HashMap<String, (Uuid, VmHandle)>>,
    
    /// Mapping of instance IDs to sets of URLs
    instance_to_urls: RwLock<HashMap<Uuid, Vec<String>>>,
    
    /// TLS configuration
    tls_config: RwLock<TlsConfig>,
}

impl UrlResolver {
    /// Creates a new URL resolver
    pub fn new() -> Self {
        Self {
            url_to_instance: RwLock::new(HashMap::new()),
            instance_to_urls: RwLock::new(HashMap::new()),
            tls_config: RwLock::new(TlsConfig::default()),
        }
    }
    
    /// Associates a URL with a VM instance
    pub fn associate(&self, url: &str, instance_id: Uuid, instance: VmHandle) -> Result<(), UrlResolverError> {
        // Parse URL
        let parsed_url = Url::parse(url)
            .map_err(|_| UrlResolverError::InvalidUrl(url.to_string()))?;
        
        // Enforce HTTPS-only
        if parsed_url.scheme() != "https" {
            return Err(UrlResolverError::InsecureUrl(
                format!("Only HTTPS URLs are allowed. Got: {}", url)
            ));
        }
        
        let url_str = parsed_url.to_string();
        
        // Check if URL is already associated
        {
            let url_map = self.url_to_instance.read().map_err(|e| {
                UrlResolverError::Internal(format!("Failed to acquire read lock: {}", e))
            })?;
            
            if url_map.contains_key(&url_str) {
                return Err(UrlResolverError::UrlAlreadyAssociated(url_str));
            }
        }
        
        // Associate URL with instance
        {
            let mut url_map = self.url_to_instance.write().map_err(|e| {
                UrlResolverError::Internal(format!("Failed to acquire write lock: {}", e))
            })?;
            
            url_map.insert(url_str.clone(), (instance_id, instance.clone()));
        }
        
        // Update instance to URLs mapping
        {
            let mut instance_map = self.instance_to_urls.write().map_err(|e| {
                UrlResolverError::Internal(format!("Failed to acquire write lock: {}", e))
            })?;
            
            let urls = instance_map.entry(instance_id).or_insert_with(Vec::new);
            if !urls.contains(&url_str) {
                urls.push(url_str);
            }
        }
        
        Ok(())
    }
    
    /// Resolves a URL to a VM instance
    pub fn resolve(&self, url: &str) -> Option<VmHandle> {
        // Parse URL
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return None,
        };
        
        let url_str = parsed_url.to_string();
        
        // Look up in map
        match self.url_to_instance.read() {
            Ok(url_map) => url_map.get(&url_str).map(|(_, instance)| instance.clone()),
            Err(e) => {
                tracing::error!("Failed to acquire URL map lock: {}", e);
                None
            }
        }
    }
    
    /// Removes all URL associations for a VM instance
    pub fn remove_instance(&self, instance_id: Uuid) -> Result<(), UrlResolverError> {
        // Get URLs for this instance
        let urls = {
            let instance_map = self.instance_to_urls.read().map_err(|e| {
                UrlResolverError::Internal(format!("Failed to acquire read lock: {}", e))
            })?;
            
            match instance_map.get(&instance_id) {
                Some(urls) => urls.clone(),
                None => return Ok(()), // Nothing to do
            }
        };
        
        // Remove from URL to instance mapping
        {
            let mut url_map = self.url_to_instance.write().map_err(|e| {
                UrlResolverError::Internal(format!("Failed to acquire write lock: {}", e))
            })?;
            
            for url in &urls {
                url_map.remove(url);
            }
        }
        
        // Remove from instance to URLs mapping
        {
            let mut instance_map = self.instance_to_urls.write().map_err(|e| {
                UrlResolverError::Internal(format!("Failed to acquire write lock: {}", e))
            })?;
            
            instance_map.remove(&instance_id);
        }
        
        Ok(())
    }
    
    /// Get all URLs for a VM instance
    pub fn get_urls_for_instance(&self, instance_id: Uuid) -> Result<Vec<String>, UrlResolverError> {
        let instance_map = self.instance_to_urls.read().map_err(|e| {
            UrlResolverError::Internal(format!("Failed to acquire read lock: {}", e))
        })?;
        
        match instance_map.get(&instance_id) {
            Some(urls) => Ok(urls.clone()),
            None => Ok(Vec::new()),
        }
    }
    
    /// Sets the TLS configuration
    pub fn set_tls_config(&self, config: TlsConfig) -> Result<(), UrlResolverError> {
        // Verify TLS config is secure
        if !config.enabled {
            return Err(UrlResolverError::InsecureConfiguration("TLS must be enabled".to_string()));
        }
        
        // Ensure mTLS for stronger security
        if !config.enable_mtls {
            return Err(UrlResolverError::InsecureConfiguration("mTLS must be enabled for enterprise security".to_string()));
        }
        
        let mut tls_config = self.tls_config.write().map_err(|e| {
            UrlResolverError::Internal(format!("Failed to acquire write lock: {}", e))
        })?;
        
        *tls_config = config;
        
        Ok(())
    }
    
    /// Gets the minimum TLS version
    pub fn get_tls_min_version(&self) -> TlsVersion {
        match self.tls_config.read() {
            Ok(tls_config) => tls_config.min_version,
            Err(_) => {
                tracing::warn!("Failed to read TLS config, using default TLS version");
                TlsVersion::default()
            }
        }
    }
    
    /// Checks if mutual TLS is enabled
    pub fn is_mtls_enabled(&self) -> bool {
        match self.tls_config.read() {
            Ok(tls_config) => tls_config.enable_mtls,
            Err(_) => {
                tracing::warn!("Failed to read TLS config, assuming mTLS is disabled");
                false
            }
        }
    }
    
    /// Gets the client CA certificate path
    pub fn get_client_ca_path(&self) -> Option<String> {
        match self.tls_config.read() {
            Ok(tls_config) => tls_config.client_ca_path.clone(),
            Err(_) => {
                tracing::warn!("Failed to read TLS config, no client CA path available");
                None
            }
        }
    }
    
    /// Checks if client certificate verification is required
    pub fn is_client_cert_required(&self) -> bool {
        match self.tls_config.read() {
            Ok(tls_config) => tls_config.require_client_cert,
            Err(_) => {
                tracing::warn!("Failed to read TLS config, assuming client cert is not required");
                false
            }
        }
    }
}

/// Error during URL resolution
#[derive(Debug, thiserror::Error)]
pub enum UrlResolverError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    
    #[error("URL already associated: {0}")]
    UrlAlreadyAssociated(String),
    
    #[error("Instance not found: {0}")]
    InstanceNotFound(Uuid),
    
    #[error("Insecure URL: {0}")]
    InsecureUrl(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
    
    #[error("Insecure configuration: {0}")]
    InsecureConfiguration(String),
} 