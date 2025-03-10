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
        // Parse URL to validate it
        let parsed_url = Url::parse(url)
            .map_err(|e| UrlResolverError::InvalidUrl(format!("Invalid URL '{}': {}", url, e)))?;
        
        let url_str = parsed_url.to_string();
        
        // Update URL to instance mapping
        {
            let mut url_map = self.url_to_instance.write().unwrap();
            url_map.insert(url_str.clone(), (instance_id, instance.clone()));
        }
        
        // Update instance to URLs mapping
        {
            let mut instance_map = self.instance_to_urls.write().unwrap();
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
        let url_map = self.url_to_instance.read().unwrap();
        url_map.get(&url_str).map(|(_, instance)| instance.clone())
    }
    
    /// Removes all URL associations for a VM instance
    pub fn remove_instance(&self, instance_id: Uuid) {
        // Get URLs for this instance
        let urls = {
            let instance_map = self.instance_to_urls.read().unwrap();
            match instance_map.get(&instance_id) {
                Some(urls) => urls.clone(),
                None => return,
            }
        };
        
        // Remove from URL to instance mapping
        {
            let mut url_map = self.url_to_instance.write().unwrap();
            for url in &urls {
                url_map.remove(url);
            }
        }
        
        // Remove from instance to URLs mapping
        {
            let mut instance_map = self.instance_to_urls.write().unwrap();
            instance_map.remove(&instance_id);
        }
    }
    
    /// Get all URLs for a VM instance
    pub fn get_urls_for_instance(&self, instance_id: Uuid) -> Vec<String> {
        let instance_map = self.instance_to_urls.read().unwrap();
        match instance_map.get(&instance_id) {
            Some(urls) => urls.clone(),
            None => Vec::new(),
        }
    }
    
    /// Sets the TLS configuration
    pub fn set_tls_config(&self, config: TlsConfig) {
        let mut tls_config = self.tls_config.write().unwrap();
        *tls_config = config;
    }
    
    /// Gets the minimum TLS version
    pub fn get_tls_min_version(&self) -> TlsVersion {
        let tls_config = self.tls_config.read().unwrap();
        tls_config.min_version.clone()
    }
    
    /// Checks if mutual TLS is enabled
    pub fn is_mtls_enabled(&self) -> bool {
        let tls_config = self.tls_config.read().unwrap();
        tls_config.enable_mtls
    }
    
    /// Gets the client CA certificate path
    pub fn get_client_ca_path(&self) -> Option<String> {
        let tls_config = self.tls_config.read().unwrap();
        tls_config.client_ca_path.clone()
    }
    
    /// Checks if client certificate verification is required
    pub fn is_client_cert_required(&self) -> bool {
        let tls_config = self.tls_config.read().unwrap();
        tls_config.require_client_cert
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
} 