// src/service/mod.rs

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use thiserror::Error;

use crate::config::{ConfigManager, VmConfig};
use crate::execution::{ExecutionEngine, ExecutionPriority, ResourceLimits, SecurityContext};
use crate::network::{ProxyServer, ProxyConfig, url_resolver::UrlResolver};
use crate::sandbox::{RootlessSandbox, RootlessSandboxConfig, IsolationLevel};
use crate::security::{api_keys::ApiKeyManager, data_guard::DataGuard, wx_enforcer::WxEnforcer};
use crate::vm::{Instance, InstanceStatus};

/// Service command for inter-component communication
#[derive(Debug)]
pub enum ServiceCommand {
    /// Create a new VM instance
    CreateInstance(VmConfig, oneshot::Sender<Result<Uuid, ServiceError>>),
    
    /// Start an existing VM instance
    StartInstance(Uuid, oneshot::Sender<Result<(), ServiceError>>),
    
    /// Stop an existing VM instance
    StopInstance(Uuid, oneshot::Sender<Result<(), ServiceError>>),
    
    /// Destroy an existing VM instance
    DestroyInstance(Uuid, oneshot::Sender<Result<(), ServiceError>>),
    
    /// Get instance status
    GetInstanceStatus(Uuid, oneshot::Sender<Result<InstanceStatus, ServiceError>>),
    
    /// Associate a URL with an instance
    AssociateUrl(Uuid, String, oneshot::Sender<Result<(), ServiceError>>),
    
    /// Create a mirror of an instance
    CreateMirror(Uuid, oneshot::Sender<Result<Uuid, ServiceError>>),
    
    /// Execute a command in an instance
    ExecuteCommand(Uuid, String, Vec<String>, oneshot::Sender<Result<ExecuteResult, ServiceError>>),
    
    /// Create an API key
    CreateApiKey(ApiKeyConfig, oneshot::Sender<Result<String, ServiceError>>),
    
    /// Validate an API key
    ValidateApiKey(String, Vec<ApiKeyScope>, oneshot::Sender<Result<ApiKeyValidationResult, ServiceError>>),
    
    /// Revoke an API key
    RevokeApiKey(Uuid, oneshot::Sender<Result<(), ServiceError>>),
    
    /// Shutdown the service
    Shutdown(oneshot::Sender<Result<(), ServiceError>>),
}

/// Result of command execution
#[derive(Debug, Clone)]
pub struct ExecuteResult {
    /// Exit code
    pub exit_code: i32,
    
    /// Standard output
    pub stdout: String,
    
    /// Standard error
    pub stderr: String,
    
    /// Execution duration in milliseconds
    pub duration_ms: u64,
}

/// API key configuration
#[derive(Debug, Clone)]
pub struct ApiKeyConfig {
    /// API key name
    pub name: String,
    
    /// API key type
    pub key_type: ApiKeyType,
    
    /// API key scopes
    pub scopes: Vec<ApiKeyScope>,
    
    /// Expiration time (if any)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    
    /// Rate limit in requests per minute (0 = unlimited)
    pub rate_limit_rpm: u32,
    
    /// Associated instance ID (if any)
    pub instance_id: Option<Uuid>,
}

/// API key type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Main service coordination layer
pub struct Service {
    /// Service command channel
    command_tx: mpsc::Sender<ServiceCommand>,
}

/// Service implementation for NanoVM
struct ServiceImpl {
    /// Configuration manager
    config_manager: ConfigManager,
    
    /// URL resolver
    url_resolver: Arc<UrlResolver>,
    
    /// Data Guard
    data_guard: Arc<DataGuard>,
    
    /// W^X enforcer
    wx_enforcer: Arc<WxEnforcer>,
    
    /// Execution engine
    execution_engine: Arc<ExecutionEngine>,
    
    /// API key manager
    api_key_manager: Arc<ApiKeyManager>,
    
    /// Proxy server
    proxy_server: Arc<ProxyServer>,
    
    /// VM instances
    instances: HashMap<Uuid, Arc<Instance>>,
    
    /// Sandboxes
    sandboxes: HashMap<Uuid, Arc<RootlessSandbox>>,
    
    /// Service command channel
    command_rx: mpsc::Receiver<ServiceCommand>,
}

impl Service {
    /// Creates a new service instance
    pub async fn new(config_path: &str) -> Result<Self, ServiceError> {
        // Create command channel
        let (command_tx, command_rx) = mpsc::channel(1000);
        
        // Load configuration
        let config_manager = ConfigManager::load_from_file(config_path)
            .map_err(|e| ServiceError::ConfigurationError(e.to_string()))?;
        
        // Initialize URL resolver
        let url_resolver = Arc::new(UrlResolver::new());
        
        // Initialize security components
        let (data_guard, _) = DataGuard::new(config_manager.get_config().security.data_guard.clone())
            .map_err(|e| ServiceError::SecurityError(e.to_string()))?;
        
        let data_guard = Arc::new(data_guard);
        let wx_enforcer = Arc::new(WxEnforcer::new());
        
        // Initialize API key manager
        let signing_key = b"this-would-be-a-secure-random-key-in-production";
        let api_key_manager = Arc::new(ApiKeyManager::new(data_guard.clone(), signing_key));
        
        // Initialize execution engine
        let execution_engine = Arc::new(ExecutionEngine::new(
            &config_manager.get_config().resources
        ).map_err(|e| ServiceError::ExecutionError(e.to_string()))?);
        
        // Initialize proxy server
        let proxy_config = ProxyConfig {
            http_listen_addr: "127.0.0.1:8080".parse().unwrap(),
            https_listen_addr: "127.0.0.1:8443".parse().unwrap(),
            tls_cert_path: None,
            tls_key_path: None,
            connection_timeout: 30,
            enable_http2: true,
            enable_access_logging: true,
            enable_health_checks: true,
            health_check_interval: 60,
        };
        
        let proxy_server = Arc::new(ProxyServer::new(
            proxy_config,
            url_resolver.clone(),
        ).await.map_err(|e| ServiceError::NetworkError(e.to_string()))?);
        
        // Create service implementation
        let service_impl = ServiceImpl {
            config_manager,
            url_resolver,
            data_guard,
            wx_enforcer,
            execution_engine,
            api_key_manager,
            proxy_server,
            instances: HashMap::new(),
            sandboxes: HashMap::new(),
            command_rx,
        };
        
        // Start service implementation
        tokio::spawn(service_impl.run());
        
        // Start proxy server
        proxy_server.start().await
            .map_err(|e| ServiceError::NetworkError(e.to_string()))?;
        
        Ok(Self {
            command_tx,
        })
    }
    
    /// Creates a new VM instance
    pub async fn create_instance(&self, config: VmConfig) -> Result<Uuid, ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::CreateInstance(config, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Starts an existing VM instance
    pub async fn start_instance(&self, instance_id: Uuid) -> Result<(), ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::StartInstance(instance_id, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Stops an existing VM instance
    pub async fn stop_instance(&self, instance_id: Uuid) -> Result<(), ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::StopInstance(instance_id, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Destroys an existing VM instance
    pub async fn destroy_instance(&self, instance_id: Uuid) -> Result<(), ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::DestroyInstance(instance_id, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Gets the status of an instance
    pub async fn get_instance_status(&self, instance_id: Uuid) -> Result<InstanceStatus, ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::GetInstanceStatus(instance_id, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Associates a URL with an instance
    pub async fn associate_url(&self, instance_id: Uuid, url: String) -> Result<(), ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::AssociateUrl(instance_id, url, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Creates a mirror of an instance
    pub async fn create_mirror(&self, instance_id: Uuid) -> Result<Uuid, ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::CreateMirror(instance_id, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Executes a command in an instance
    pub async fn execute_command(
        &self,
        instance_id: Uuid,
        command: String,
        args: Vec<String>,
    ) -> Result<ExecuteResult, ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::ExecuteCommand(instance_id, command, args, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Creates a new API key
    pub async fn create_api_key(&self, config: ApiKeyConfig) -> Result<String, ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::CreateApiKey(config, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Validates an API key
    pub async fn validate_api_key(
        &self,
        key: String,
        scopes: Vec<ApiKeyScope>,
    ) -> Result<ApiKeyValidationResult, ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::ValidateApiKey(key, scopes, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Revokes an API key
    pub async fn revoke_api_key(&self, key_id: Uuid) -> Result<(), ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::RevokeApiKey(key_id, tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
    
    /// Shuts down the service
    pub async fn shutdown(&self) -> Result<(), ServiceError> {
        let (tx, rx) = oneshot::channel();
        
        self.command_tx.send(ServiceCommand::Shutdown(tx)).await
            .map_err(|_| ServiceError::ChannelClosed)?;
        
        rx.await.map_err(|_| ServiceError::ResponseChannelClosed)?
    }
}

impl ServiceImpl {
    /// Runs the service implementation
    async fn run(mut self) {
        info!("Service started");
        
        while let Some(command) = self.command_rx.recv().await {
            match command {
                ServiceCommand::CreateInstance(config, response_tx) => {
                    let result = self.handle_create_instance(config).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send create instance response");
                    }
                }
                ServiceCommand::StartInstance(instance_id, response_tx) => {
                    let result = self.handle_start_instance(instance_id).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send start instance response");
                    }
                }
                ServiceCommand::StopInstance(instance_id, response_tx) => {
                    let result = self.handle_stop_instance(instance_id).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send stop instance response");
                    }
                }
                ServiceCommand::DestroyInstance(instance_id, response_tx) => {
                    let result = self.handle_destroy_instance(instance_id).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send destroy instance response");
                    }
                }
                ServiceCommand::GetInstanceStatus(instance_id, response_tx) => {
                    let result = self.handle_get_instance_status(instance_id).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send get instance status response");
                    }
                }
                ServiceCommand::AssociateUrl(instance_id, url, response_tx) => {
                    let result = self.handle_associate_url(instance_id, url).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send associate URL response");
                    }
                }
                ServiceCommand::CreateMirror(instance_id, response_tx) => {
                    let result = self.handle_create_mirror(instance_id).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send create mirror response");
                    }
                }
                ServiceCommand::ExecuteCommand(instance_id, command, args, response_tx) => {
                    let result = self.handle_execute_command(instance_id, command, args).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send execute command response");
                    }
                }
                ServiceCommand::CreateApiKey(config, response_tx) => {
                    let result = self.handle_create_api_key(config).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send create API key response");
                    }
                }
                ServiceCommand::ValidateApiKey(key, scopes, response_tx) => {
                    let result = self.handle_validate_api_key(key, scopes).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send validate API key response");
                    }
                }
                ServiceCommand::RevokeApiKey(key_id, response_tx) => {
                    let result = self.handle_revoke_api_key(key_id).await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send revoke API key response");
                    }
                }
                ServiceCommand::Shutdown(response_tx) => {
                    let result = self.handle_shutdown().await;
                    if let Err(_) = response_tx.send(result) {
                        error!("Failed to send shutdown response");
                    }
                    
                    // Exit the service loop
                    break;
                }
            }
        }
        
        info!("Service stopped");
    }
    
    /// Handles creating a new VM instance
    async fn handle_create_instance(&mut self, config: VmConfig) -> Result<Uuid, ServiceError> {
        // Create a new instance
        let instance = Instance::new(
            config,
            self.url_resolver.clone(),
            self.data_guard.clone(),
            self.wx_enforcer.clone(),
        ).await.map_err(|e| ServiceError::VmError(e.to_string()))?;
        
        // Get the instance ID
        let instance_id = instance.id;
        
        // Store the instance
        self.instances.insert(instance_id, Arc::new(instance));
        
        // Create a sandbox for the instance
        let sandbox_config = RootlessSandboxConfig {
            isolation_level: IsolationLevel::Namespace,
            limits: crate::sandbox::SandboxLimits {
                memory_limit_bytes: config.resources.memory_limit_bytes,
                cpu_limit: (config.resources.cpu_limit * 100.0) as u32,
                process_limit: 100,
                fs_size_limit_bytes: config.resources.storage_limit_bytes,
                open_files_limit: 1000,
            },
            working_dir: std::path::PathBuf::from("/tmp"),
            env_vars: HashMap::new(),
            allowed_paths: std::collections::HashSet::new(),
            allowed_syscalls: std::collections::HashSet::new(),
            network_policy: crate::sandbox::NetworkPolicy::Isolated,
            enable_seccomp: true,
        };
        
        let sandbox = RootlessSandbox::new(
            sandbox_config,
            self.data_guard.clone(),
        ).map_err(|e| ServiceError::SandboxError(e.to_string()))?;
        
        // Store the sandbox
        self.sandboxes.insert(instance_id, Arc::new(sandbox));
        
        info!("Created new VM instance: {}", instance_id);
        
        Ok(instance_id)
    }
    
    /// Handles starting a VM instance
    async fn handle_start_instance(&mut self, instance_id: Uuid) -> Result<(), ServiceError> {
        // Find the instance
        let instance = self.instances.get(&instance_id)
            .ok_or_else(|| ServiceError::InstanceNotFound(instance_id))?;
        
        // Find the sandbox
        let sandbox = self.sandboxes.get(&instance_id)
            .ok_or_else(|| ServiceError::SandboxNotFound(instance_id))?;
        
        // Start the sandbox
        sandbox.start().await
            .map_err(|e| ServiceError::SandboxError(e.to_string()))?;
        
        // Start the instance
        instance.start().await
            .map_err(|e| ServiceError::VmError(e.to_string()))?;
        
        info!("Started VM instance: {}", instance_id);
        
        Ok(())
    }
    
    /// Handles stopping a VM instance
    async fn handle_stop_instance(&mut self, instance_id: Uuid) -> Result<(), ServiceError> {
        // Find the instance
        let instance = self.instances.get(&instance_id)
            .ok_or_else(|| ServiceError::InstanceNotFound(instance_id))?;
        
        // Find the sandbox
        let sandbox = self.sandboxes.get(&instance_id)
            .ok_or_else(|| ServiceError::SandboxNotFound(instance_id))?;
        
        // Stop the instance
        instance.stop().await
            .map_err(|e| ServiceError::VmError(e.to_string()))?;
        
        // Stop the sandbox
        sandbox.stop().await
            .map_err(|e| ServiceError::SandboxError(e.to_string()))?;
        
        info!("Stopped VM instance: {}", instance_id);
        
        Ok(())
    }
    
    /// Handles destroying a VM instance
    async fn handle_destroy_instance(&mut self, instance_id: Uuid) -> Result<(), ServiceError> {
        // Find the instance
        let instance = self.instances.get(&instance_id)
            .ok_or_else(|| ServiceError::InstanceNotFound(instance_id))?;
        
        // Check if the instance is running
        if instance.get_status().await == InstanceStatus::Running {
            // Stop the instance first
            self.handle_stop_instance(instance_id).await?;
        }
        
        // Remove instance
        self.instances.remove(&instance_id);
        
        // Remove sandbox
        self.sandboxes.remove(&instance_id);
        
        // Remove URL associations
        self.url_resolver.remove_instance(instance_id);
        
        info!("Destroyed VM instance: {}", instance_id);
        
        Ok(())
    }
    
    /// Handles getting instance status
    async fn handle_get_instance_status(&self, instance_id: Uuid) -> Result<InstanceStatus, ServiceError> {
        // Find the instance
        let instance = self.instances.get(&instance_id)
            .ok_or_else(|| ServiceError::InstanceNotFound(instance_id))?;
        
        // Get the status
        let status = instance.get_status().await;
        
        Ok(status)
    }
    
    /// Handles associating a URL with an instance
    async fn handle_associate_url(&self, instance_id: Uuid, url: String) -> Result<(), ServiceError> {
        // Find the instance
        let instance = self.instances.get(&instance_id)
            .ok_or_else(|| ServiceError::InstanceNotFound(instance_id))?;
        
        // Associate URL
        self.url_resolver.associate(
            &url,
            instance_id,
            instance.clone(),
        ).map_err(|e| ServiceError::NetworkError(e.to_string()))?;
        
        info!("Associated URL {} with instance {}", url, instance_id);
        
        Ok(())
    }
    
    /// Handles creating a mirror of an instance
    async fn handle_create_mirror(&mut self, instance_id: Uuid) -> Result<Uuid, ServiceError> {
        // Find the source instance
        let source_instance = self.instances.get(&instance_id)
            .ok_or_else(|| ServiceError::InstanceNotFound(instance_id))?;
        
        // Get the source configuration
        let source_config = source_instance.get_config().await
            .map_err(|e| ServiceError::VmError(e.to_string()))?;
        
        // Create a new instance with the same configuration
        let mirror_instance = Instance::new(
            source_config.clone(),
            self.url_resolver.clone(),
            self.data_guard.clone(),
            self.wx_enforcer.clone(),
        ).await.map_err(|e| ServiceError::VmError(e.to_string()))?;
        
        // Get the mirror instance ID
        let mirror_id = mirror_instance.id;
        
        // Store the mirror instance
        self.instances.insert(mirror_id, Arc::new(mirror_instance));
        
        // Create a sandbox for the mirror instance
        let sandbox_config = RootlessSandboxConfig {
            isolation_level: IsolationLevel::Namespace,
            limits: crate::sandbox::SandboxLimits {
                memory_limit_bytes: source_config.resources.memory_limit_bytes,
                cpu_limit: (source_config.resources.cpu_limit * 100.0) as u32,
                process_limit: 100,
                fs_size_limit_bytes: source_config.resources.storage_limit_bytes,
                open_files_limit: 1000,
            },
            working_dir: std::path::PathBuf::from("/tmp"),
            env_vars: HashMap::new(),
            allowed_paths: std::collections::HashSet::new(),
            allowed_syscalls: std::collections::HashSet::new(),
            network_policy: crate::sandbox::NetworkPolicy::Isolated,
            enable_seccomp: true,
        };
        
        let sandbox = RootlessSandbox::new(
            sandbox_config,
            self.data_guard.clone(),
        ).map_err(|e| ServiceError::SandboxError(e.to_string()))?;
        
        // Store the sandbox
        self.sandboxes.insert(mirror_id, Arc::new(sandbox));
        
        // Copy URL associations
        let urls = self.url_resolver.get_instance_urls(instance_id);
        for url in urls {
            self.url_resolver.associate(
                &url,
                mirror_id,
                self.instances.get(&mirror_id).unwrap().clone(),
            ).map_err(|e| ServiceError::NetworkError(e.to_string()))?;
        }
        
        info!("Created mirror instance {} of source instance {}", mirror_id, instance_id);
        
        Ok(mirror_id)
    }
    
    /// Handles executing a command in an instance
    async fn handle_execute_command(
        &self,
        instance_id: Uuid,
        command: String,
        args: Vec<String>,
    ) -> Result<ExecuteResult, ServiceError> {
        // Find the instance
        let instance = self.instances.get(&instance_id)
            .ok_or_else(|| ServiceError::InstanceNotFound(instance_id))?;
        
        // Find the sandbox
        let sandbox = self.sandboxes.get(&instance_id)
            .ok_or_else(|| ServiceError::SandboxNotFound(instance_id))?;
        
        // Check if the instance is running
        if instance.get_status().await != InstanceStatus::Running {
            return Err(ServiceError::InstanceNotRunning(instance_id));
        }
        
        // Execute the command in the sandbox
        let result = sandbox.exec(
            command,
            &args,
            None,
            None,
            Some(30),
        ).await.map_err(|e| ServiceError::SandboxError(e.to_string()))?;
        
        // Convert the result
        let execute_result = ExecuteResult {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            duration_ms: result.duration_ms,
        };
        
        Ok(execute_result)
    }
    
    /// Handles creating a new API key
    async fn handle_create_api_key(&self, config: ApiKeyConfig) -> Result<String, ServiceError> {
        // Convert to internal API key config
        let internal_config = crate::security::api_keys::ApiKeyConfig {
            id: Uuid::new_v4(),
            name: config.name,
            key_type: match config.key_type {
                ApiKeyType::Master => crate::security::api_keys::ApiKeyType::Master,
                ApiKeyType::Admin => crate::security::api_keys::ApiKeyType::Admin,
                ApiKeyType::User => crate::security::api_keys::ApiKeyType::User,
                ApiKeyType::Service => crate::security::api_keys::ApiKeyType::Service,
                ApiKeyType::Temporary => crate::security::api_keys::ApiKeyType::Temporary,
            },
            scopes: config.scopes.into_iter().map(|scope| match scope {
                ApiKeyScope::FullAccess => crate::security::api_keys::ApiKeyScope::FullAccess,
                ApiKeyScope::ReadOnly => crate::security::api_keys::ApiKeyScope::ReadOnly,
                ApiKeyScope::WriteOnly => crate::security::api_keys::ApiKeyScope::WriteOnly,
                ApiKeyScope::Resource(name) => crate::security::api_keys::ApiKeyScope::Resource(name),
                ApiKeyScope::Action(name) => crate::security::api_keys::ApiKeyScope::Action(name),
                ApiKeyScope::Instance(id) => crate::security::api_keys::ApiKeyScope::Instance(id),
            }).collect(),
            expires_at: config.expires_at,
            rate_limit_rpm: config.rate_limit_rpm,
            instance_id: config.instance_id,
            created_at: chrono::Utc::now(),
            last_used_at: None,
            metadata: HashMap::new(),
        };
        
        // Create the API key
        let key = self.api_key_manager.create_key(internal_config)
            .map_err(|e| ServiceError::SecurityError(e.to_string()))?;
        
        Ok(key)
    }
    
    /// Handles validating an API key
    async fn handle_validate_api_key(
        &self,
        key: String,
        scopes: Vec<ApiKeyScope>,
    ) -> Result<ApiKeyValidationResult, ServiceError> {
        // Convert scopes to internal format
        let internal_scopes: Vec<crate::security::api_keys::ApiKeyScope> = scopes.into_iter()
            .map(|scope| match scope {
                ApiKeyScope::FullAccess => crate::security::api_keys::ApiKeyScope::FullAccess,
                ApiKeyScope::ReadOnly => crate::security::api_keys::ApiKeyScope::ReadOnly,
                ApiKeyScope::WriteOnly => crate::security::api_keys::ApiKeyScope::WriteOnly,
                ApiKeyScope::Resource(name) => crate::security::api_keys::ApiKeyScope::Resource(name),
                ApiKeyScope::Action(name) => crate::security::api_keys::ApiKeyScope::Action(name),
                ApiKeyScope::Instance(id) => crate::security::api_keys::ApiKeyScope::Instance(id),
            })
            .collect();
        
        // Validate the key
        let result = self.api_key_manager.validate_key(&key, &internal_scopes, None).await;
        
        // Convert the result to the service API format
        let validation_result = ApiKeyValidationResult {
            valid: result.valid,
            config: result.config.map(|config| ApiKeyConfig {
                name: config.name,
                key_type: match config.key_type {
                    crate::security::api_keys::ApiKeyType::Master => ApiKeyType::Master,
                    crate::security::api_keys::ApiKeyType::Admin => ApiKeyType::Admin,
                    crate::security::api_keys::ApiKeyType::User => ApiKeyType::User,
                    crate::security::api_keys::ApiKeyType::Service => ApiKeyType::Service,
                    crate::security::api_keys::ApiKeyType::Temporary => ApiKeyType::Temporary,
                },
                scopes: config.scopes.into_iter().map(|scope| match scope {
                    crate::security::api_keys::ApiKeyScope::FullAccess => ApiKeyScope::FullAccess,
                    crate::security::api_keys::ApiKeyScope::ReadOnly => ApiKeyScope::ReadOnly,
                    crate::security::api_keys::ApiKeyScope::WriteOnly => ApiKeyScope::WriteOnly,
                    crate::security::api_keys::ApiKeyScope::Resource(name) => ApiKeyScope::Resource(name),
                    crate::security::api_keys::ApiKeyScope::Action(name) => ApiKeyScope::Action(name),
                    crate::security::api_keys::ApiKeyScope::Instance(id) => ApiKeyScope::Instance(id),
                }).collect(),
                expires_at: config.expires_at,
                rate_limit_rpm: config.rate_limit_rpm,
                instance_id: config.instance_id,
            }),
            error: result.error.map(|error| match error {
                crate::security::api_keys::ApiKeyValidationError::NotFound => ApiKeyValidationError::NotFound,
                crate::security::api_keys::ApiKeyValidationError::Expired => ApiKeyValidationError::Expired,
                crate::security::api_keys::ApiKeyValidationError::Disabled => ApiKeyValidationError::Disabled,
                crate::security::api_keys::ApiKeyValidationError::Revoked => ApiKeyValidationError::Revoked,
                crate::security::api_keys::ApiKeyValidationError::ScopeMismatch => ApiKeyValidationError::ScopeMismatch,
                crate::security::api_keys::ApiKeyValidationError::RateLimited => ApiKeyValidationError::RateLimited,
                crate::security::api_keys::ApiKeyValidationError::InstanceMismatch => ApiKeyValidationError::InstanceMismatch,
            }),
        };
        
        Ok(validation_result)
    }
    
    /// Handles revoking an API key
    async fn handle_revoke_api_key(&self, key_id: Uuid) -> Result<(), ServiceError> {
        // Revoke the key
        self.api_key_manager.revoke_key(key_id)
            .map_err(|e| ServiceError::SecurityError(e.to_string()))?;
        
        Ok(())
    }
    
    /// Handles shutting down the service
    async fn handle_shutdown(&self) -> Result<(), ServiceError> {
        // Stop all instances
        for (instance_id, instance) in &self.instances {
            if instance.get_status().await == InstanceStatus::Running {
                instance.stop().await
                    .map_err(|e| ServiceError::VmError(e.to_string()))?;
                
                info!("Stopped VM instance: {}", instance_id);
            }
        }
        
        // Stop all sandboxes
        for (instance_id, sandbox) in &self.sandboxes {
            if sandbox.get_state() == crate::sandbox::SandboxState::Running {
                sandbox.stop().await
                    .map_err(|e| ServiceError::SandboxError(e.to_string()))?;
                
                info!("Stopped sandbox for instance: {}", instance_id);
            }
        }
        
        // Stop the proxy server
        self.proxy_server.stop().await
            .map_err(|e| ServiceError::NetworkError(e.to_string()))?;
        
        info!("Stopped proxy server");
        
        Ok(())
    }
}

/// Error during service operations
#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("VM error: {0}")]
    VmError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Security error: {0}")]
    SecurityError(String),
    
    #[error("Sandbox error: {0}")]
    SandboxError(String),
    
    #[error("Execution error: {0}")]
    ExecutionError(String),
    
    #[error("Instance not found: {0}")]
    InstanceNotFound(Uuid),
    
    #[error("Sandbox not found: {0}")]
    SandboxNotFound(Uuid),
    
    #[error("Instance not running: {0}")]
    InstanceNotRunning(Uuid),
    
    #[error("Channel closed")]
    ChannelClosed,
    
    #[error("Response channel closed")]
    ResponseChannelClosed,
    
    #[error("Internal error: {0}")]
    Internal(String),
}