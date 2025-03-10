// src/network/proxy.rs

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, instrument, trace, warn};
use url::Url;
use uuid::Uuid;
use thiserror::Error;

use crate::config::NetworkConfig;
use crate::network::url_resolver::UrlResolver;
use crate::vm::Instance;

/// Maximum number of concurrent connections
const MAX_CONCURRENT_CONNECTIONS: usize = 10_000;

/// Buffer size for proxying data
const PROXY_BUFFER_SIZE: usize = 64 * 1024;

/// Proxy statistics
#[derive(Debug, Clone, Default)]
pub struct ProxyStats {
    /// Total number of connections handled
    pub total_connections: u64,
    
    /// Number of active connections
    pub active_connections: u64,
    
    /// Number of bytes received
    pub bytes_received: u64,
    
    /// Number of bytes sent
    pub bytes_sent: u64,
    
    /// Number of routing errors
    pub routing_errors: u64,
    
    /// Number of connection errors
    pub connection_errors: u64,
    
    /// Number of TLS errors
    pub tls_errors: u64,
    
    /// Number of timeouts
    pub timeouts: u64,
    
    /// Average response time in milliseconds
    pub avg_response_time_ms: u64,
    
    /// 95th percentile response time in milliseconds
    pub p95_response_time_ms: u64,
    
    /// 99th percentile response time in milliseconds
    pub p99_response_time_ms: u64,
}

/// Connection health check result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Service is healthy and responding
    Healthy,
    
    /// Service is responding but with degraded performance
    Degraded,
    
    /// Service is not responding or unhealthy
    Unhealthy,
}

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// HTTP listen address
    pub http_listen_addr: SocketAddr,
    
    /// HTTPS listen address
    pub https_listen_addr: SocketAddr,
    
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    
    /// TLS private key path
    pub tls_key_path: Option<String>,
    
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    
    /// Whether to enable HTTP/2
    pub enable_http2: bool,
    
    /// Whether to enable access logging
    pub enable_access_logging: bool,
    
    /// Whether to enable health checks
    pub enable_health_checks: bool,
    
    /// Health check interval in seconds
    pub health_check_interval: u64,
}

/// Proxy server for handling inbound connections
pub struct ProxyServer {
    /// Unique identifier for this proxy server
    id: Uuid,
    
    /// Proxy configuration
    config: ProxyConfig,
    
    /// URL resolver for routing requests
    url_resolver: Arc<UrlResolver>,
    
    /// TLS acceptor for HTTPS connections
    tls_acceptor: Option<TlsAcceptor>,
    
    /// Active connections
    active_connections: Arc<RwLock<HashMap<Uuid, ConnectionInfo>>>,
    
    /// Proxy statistics
    stats: Arc<RwLock<ProxyStats>>,
    
    /// Shutdown channel
    shutdown_tx: mpsc::Sender<()>,
}

/// Connection information
struct ConnectionInfo {
    /// Unique identifier for this connection
    id: Uuid,
    
    /// Remote address
    remote_addr: SocketAddr,
    
    /// Target VM instance
    target_instance: Option<Arc<RwLock<Instance>>>,
    
    /// Connection start time
    start_time: chrono::DateTime<chrono::Utc>,
    
    /// Target URL
    target_url: Option<Url>,
    
    /// Whether this is a TLS connection
    is_tls: bool,
    
    /// Bytes received
    bytes_received: u64,
    
    /// Bytes sent
    bytes_sent: u64,
}

impl ProxyServer {
    /// Creates a new proxy server
    pub async fn new(
        config: ProxyConfig,
        url_resolver: Arc<UrlResolver>,
    ) -> Result<Self, ProxyError> {
        // Create shutdown channel
        let (shutdown_tx, _) = mpsc::channel(1);
        
        // Initialize TLS acceptor if TLS is enabled
        let tls_acceptor = if let (Some(cert_path), Some(key_path)) = 
            (&config.tls_cert_path, &config.tls_key_path) {
            
            // Load certificate
            let cert_file = tokio::fs::read(cert_path).await.map_err(|e| {
                ProxyError::TlsConfigError(format!("Failed to read certificate file: {}", e))
            })?;
            
            let key_file = tokio::fs::read(key_path).await.map_err(|e| {
                ProxyError::TlsConfigError(format!("Failed to read key file: {}", e))
            })?;
            
            // Parse certificate
            let cert = rustls_pemfile::certs(&mut cert_file.as_slice())
                .map_err(|e| ProxyError::TlsConfigError(format!("Failed to parse certificate: {}", e)))?
                .into_iter()
                .map(Certificate)
                .collect();
            
            // Parse private key
            let key = rustls_pemfile::pkcs8_private_keys(&mut key_file.as_slice())
                .map_err(|e| ProxyError::TlsConfigError(format!("Failed to parse private key: {}", e)))?
                .into_iter()
                .map(PrivateKey)
                .next()
                .ok_or_else(|| ProxyError::TlsConfigError("No private key found".to_string()))?;
            
            // Configure TLS
            let mut tls_config_builder = rustls::ServerConfig::builder();
            
            // Set TLS protocol versions based on config
            let min_protocol_version = match url_resolver.get_tls_min_version() {
                crate::config::TlsVersion::V1_0 => rustls::ProtocolVersion::TLSv1_0,
                crate::config::TlsVersion::V1_1 => rustls::ProtocolVersion::TLSv1_1,
                crate::config::TlsVersion::V1_2 => rustls::ProtocolVersion::TLSv1_2,
                crate::config::TlsVersion::V1_3 => rustls::ProtocolVersion::TLSv1_3,
            };
            
            // Ensure TLS 1.2 is the minimum
            if min_protocol_version < rustls::ProtocolVersion::TLSv1_2 {
                warn!("TLS version below 1.2 requested, forcing minimum of TLS 1.2");
                tls_config_builder = tls_config_builder.with_protocol_versions(&[rustls::ProtocolVersion::TLSv1_2, rustls::ProtocolVersion::TLSv1_3])
                    .map_err(|e| ProxyError::TlsConfigError(format!("Failed to set TLS protocol versions: {}", e)))?;
            } else {
                tls_config_builder = tls_config_builder.with_protocol_versions(&[min_protocol_version, rustls::ProtocolVersion::TLSv1_3])
                    .map_err(|e| ProxyError::TlsConfigError(format!("Failed to set TLS protocol versions: {}", e)))?;
            }
            
            // Configure client certificate verification (mTLS)
            let tls_config = if url_resolver.is_mtls_enabled() {
                // Get client CA path
                let client_ca_path = url_resolver.get_client_ca_path().ok_or_else(|| {
                    ProxyError::TlsConfigError("mTLS enabled but no client CA certificate provided".to_string())
                })?;
                
                // Load client CA certificates
                let client_ca_file = tokio::fs::read(client_ca_path).await.map_err(|e| {
                    ProxyError::TlsConfigError(format!("Failed to read client CA certificate file: {}", e))
                })?;
                
                // Parse client CA certificates
                let client_ca_certs = rustls_pemfile::certs(&mut client_ca_file.as_slice())
                    .map_err(|e| ProxyError::TlsConfigError(format!("Failed to parse client CA certificate: {}", e)))?
                    .into_iter()
                    .map(Certificate)
                    .collect();
                
                // Create client certificate verifier
                let client_cert_verifier = rustls::server::AllowAnyAuthenticatedClient::new(rustls::RootCertStore {
                    roots: client_ca_certs,
                })
                .map_err(|e| ProxyError::TlsConfigError(format!("Failed to create client certificate verifier: {}", e)))?;
                
                // Configure with client certificate verification
                tls_config_builder
                    .with_client_cert_verifier(Arc::new(client_cert_verifier))
                    .with_single_cert(cert, key)
                    .map_err(|e| ProxyError::TlsConfigError(format!("TLS config error: {}", e)))?
            } else {
                // Configure without client certificate verification
                tls_config_builder
                    .with_no_client_auth()
                    .with_single_cert(cert, key)
                    .map_err(|e| ProxyError::TlsConfigError(format!("TLS config error: {}", e)))?
            };
            
            // Configure HTTP/2 if enabled
            let mut tls_config = tls_config;
            if config.enable_http2 {
                tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            
            Some(TlsAcceptor::from(Arc::new(tls_config)))
        } else {
            None
        };
        
        // Create proxy server
        let server = Self {
            id: Uuid::new_v4(),
            config,
            url_resolver,
            tls_acceptor,
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ProxyStats::default())),
            shutdown_tx,
        };
        
        Ok(server)
    }
    
    /// Starts the proxy server
    pub async fn start(&self) -> Result<(), ProxyError> {
        // Start HTTP listener
        let http_listener = TcpListener::bind(&self.config.http_listen_addr).await
            .map_err(|e| ProxyError::BindError(format!("Failed to bind HTTP listener: {}", e)))?;
        
        info!("HTTP proxy listening on {}", self.config.http_listen_addr);
        
        // Start HTTPS listener if TLS is configured
        let https_listener = if self.tls_acceptor.is_some() {
            let listener = TcpListener::bind(&self.config.https_listen_addr).await
                .map_err(|e| ProxyError::BindError(format!("Failed to bind HTTPS listener: {}", e)))?;
            
            info!("HTTPS proxy listening on {}", self.config.https_listen_addr);
            
            Some(listener)
        } else {
            None
        };
        
        // Clone references for the HTTP handler
        let url_resolver = self.url_resolver.clone();
        let active_connections = self.active_connections.clone();
        let stats = self.stats.clone();
        let connection_timeout = self.config.connection_timeout;
        let enable_access_logging = self.config.enable_access_logging;
        
        // Clone references for the HTTPS handler
        let url_resolver_https = self.url_resolver.clone();
        let active_connections_https = self.active_connections.clone();
        let stats_https = self.stats.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let connection_timeout_https = self.config.connection_timeout;
        let enable_access_logging_https = self.config.enable_access_logging;
        
        // Clone shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let shutdown_tx_clone = shutdown_tx.clone();
        
        // Spawn HTTP handler
        tokio::spawn(async move {
            loop {
                // Accept new connections with cancellation
                let accept_future = http_listener.accept();
                
                tokio::select! {
                    // Handle shutdown signal
                    _ = shutdown_rx.recv() => {
                        info!("HTTP proxy shutting down");
                        break;
                    }
                    
                    // Handle new connection
                    result = accept_future => {
                        match result {
                            Ok((stream, addr)) => {
                                // Update statistics
                                {
                                    let mut stats_guard = stats.write().unwrap();
                                    stats_guard.total_connections += 1;
                                    stats_guard.active_connections += 1;
                                }
                                
                                // Create connection ID
                                let connection_id = Uuid::new_v4();
                                
                                // Register connection
                                {
                                    let mut connections = active_connections.write().unwrap();
                                    connections.insert(connection_id, ConnectionInfo {
                                        id: connection_id,
                                        remote_addr: addr,
                                        target_instance: None,
                                        start_time: chrono::Utc::now(),
                                        target_url: None,
                                        is_tls: false,
                                        bytes_received: 0,
                                        bytes_sent: 0,
                                    });
                                }
                                
                                // Clone references for the connection handler
                                let url_resolver = url_resolver.clone();
                                let active_connections = active_connections.clone();
                                let stats = stats.clone();
                                let enable_access_logging = enable_access_logging;
                                
                                // Spawn connection handler
                                tokio::spawn(async move {
                                    // Set connection timeout
                                    let timeout = std::time::Duration::from_secs(connection_timeout);
                                    
                                    // Handle the connection with timeout
                                    match tokio::time::timeout(timeout, Self::handle_http_connection(
                                        connection_id, 
                                        stream, 
                                        addr, 
                                        url_resolver,
                                        enable_access_logging,
                                    )).await {
                                        Ok(result) => {
                                            if let Err(e) = result {
                                                debug!("HTTP connection error: {}", e);
                                                
                                                // Update statistics
                                                let mut stats_guard = stats.write().unwrap();
                                                stats_guard.connection_errors += 1;
                                            }
                                        }
                                        Err(_) => {
                                            // Connection timed out
                                            debug!("HTTP connection timed out: {}", addr);
                                            
                                            // Update statistics
                                            let mut stats_guard = stats.write().unwrap();
                                            stats_guard.timeouts += 1;
                                        }
                                    }
                                    
                                    // Clean up connection
                                    {
                                        // Calculate response time
                                        let response_time_ms = {
                                            let connections = active_connections.read().unwrap();
                                            if let Some(conn_info) = connections.get(&connection_id) {
                                                (chrono::Utc::now() - conn_info.start_time).num_milliseconds() as u64
                                            } else {
                                                0
                                            }
                                        };
                                        
                                        // Update statistics
                                        let mut stats_guard = stats.write().unwrap();
                                        stats_guard.active_connections = stats_guard.active_connections.saturating_sub(1);
                                        
                                        // Update response time metrics
                                        // In a real implementation, we would use a proper metrics implementation
                                        // that can calculate percentiles
                                        if response_time_ms > 0 {
                                            // Simple moving average for now
                                            stats_guard.avg_response_time_ms = 
                                                (stats_guard.avg_response_time_ms + response_time_ms) / 2;
                                        }
                                        
                                        // Remove connection
                                        let mut connections = active_connections.write().unwrap();
                                        connections.remove(&connection_id);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept HTTP connection: {}", e);
                            }
                        }
                    }
                }
            }
        });
        
        // Spawn HTTPS handler if configured
        if let Some(https_listener) = https_listener {
            let tls_acceptor = tls_acceptor.expect("TLS acceptor should be configured");
            
            tokio::spawn(async move {
                loop {
                    // Accept new connections with cancellation
                    let accept_future = https_listener.accept();
                    
                    tokio::select! {
                        // Handle shutdown signal
                        _ = shutdown_rx.recv() => {
                            info!("HTTPS proxy shutting down");
                            break;
                        }
                        
                        // Handle new connection
                        result = accept_future => {
                            match result {
                                Ok((stream, addr)) => {
                                    // Update statistics
                                    {
                                        let mut stats_guard = stats_https.write().unwrap();
                                        stats_guard.total_connections += 1;
                                        stats_guard.active_connections += 1;
                                    }
                                    
                                    // Create connection ID
                                    let connection_id = Uuid::new_v4();
                                    
                                    // Register connection
                                    {
                                        let mut connections = active_connections_https.write().unwrap();
                                        connections.insert(connection_id, ConnectionInfo {
                                            id: connection_id,
                                            remote_addr: addr,
                                            target_instance: None,
                                            start_time: chrono::Utc::now(),
                                            target_url: None,
                                            is_tls: true,
                                            bytes_received: 0,
                                            bytes_sent: 0,
                                        });
                                    }
                                    
                                    // Clone references for the connection handler
                                    let url_resolver = url_resolver_https.clone();
                                    let active_connections = active_connections_https.clone();
                                    let stats = stats_https.clone();
                                    let tls_acceptor = tls_acceptor.clone();
                                    let enable_access_logging = enable_access_logging_https;
                                    
                                    // Spawn connection handler
                                    tokio::spawn(async move {
                                        // Perform TLS handshake
                                        let tls_stream = match tls_acceptor.accept(stream).await {
                                            Ok(tls_stream) => tls_stream,
                                            Err(e) => {
                                                warn!("TLS handshake failed: {}", e);
                                                
                                                // Update statistics
                                                let mut stats_guard = stats.write().unwrap();
                                                stats_guard.tls_errors += 1;
                                                stats_guard.active_connections = stats_guard.active_connections.saturating_sub(1);
                                                
                                                // Remove connection
                                                let mut connections = active_connections.write().unwrap();
                                                connections.remove(&connection_id);
                                                
                                                return;
                                            }
                                        };
                                        
                                        // Set connection timeout
                                        let timeout = std::time::Duration::from_secs(connection_timeout_https);
                                        
                                        // Handle the connection with timeout
                                        match tokio::time::timeout(timeout, Self::handle_https_connection(
                                            connection_id, 
                                            tls_stream, 
                                            addr, 
                                            url_resolver,
                                            enable_access_logging,
                                        )).await {
                                            Ok(result) => {
                                                if let Err(e) = result {
                                                    debug!("HTTPS connection error: {}", e);
                                                    
                                                    // Update statistics
                                                    let mut stats_guard = stats.write().unwrap();
                                                    stats_guard.connection_errors += 1;
                                                }
                                            }
                                            Err(_) => {
                                                // Connection timed out
                                                debug!("HTTPS connection timed out: {}", addr);
                                                
                                                // Update statistics
                                                let mut stats_guard = stats.write().unwrap();
                                                stats_guard.timeouts += 1;
                                            }
                                        }
                                        
                                        // Clean up connection
                                        {
                                            // Calculate response time
                                            let response_time_ms = {
                                                let connections = active_connections.read().unwrap();
                                                if let Some(conn_info) = connections.get(&connection_id) {
                                                    (chrono::Utc::now() - conn_info.start_time).num_milliseconds() as u64
                                                } else {
                                                    0
                                                }
                                            };
                                            
                                            // Update statistics
                                            let mut stats_guard = stats.write().unwrap();
                                            stats_guard.active_connections = stats_guard.active_connections.saturating_sub(1);
                                            
                                            // Update response time metrics
                                            if response_time_ms > 0 {
                                                // Simple moving average for now
                                                stats_guard.avg_response_time_ms = 
                                                    (stats_guard.avg_response_time_ms + response_time_ms) / 2;
                                            }
                                            
                                            // Remove connection
                                            let mut connections = active_connections.write().unwrap();
                                            connections.remove(&connection_id);
                                        }
                                    });
                                }
                                Err(e) => {
                                    error!("Failed to accept HTTPS connection: {}", e);
                                }
                            }
                        }
                    }
                }
            });
        }
        
        // Start health check if enabled
        if self.config.enable_health_checks {
            let url_resolver = self.url_resolver.clone();
            let interval = self.config.health_check_interval;
            
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval));
                
                loop {
                    tokio::select! {
                        // Handle shutdown signal
                        _ = shutdown_rx.recv() => {
                            info!("Health check shutting down");
                            break;
                        }
                        
                        // Perform health check
                        _ = interval.tick() => {
                            Self::perform_health_check(url_resolver.clone()).await;
                        }
                    }
                }
            });
        }
        
        Ok(())
    }
    
    /// Stops the proxy server
    pub async fn stop(&self) -> Result<(), ProxyError> {
        // Send shutdown signal
        if let Err(e) = self.shutdown_tx.send(()).await {
            error!("Failed to send shutdown signal: {}", e);
        }
        
        // Wait for connections to drain
        let mut wait_iterations = 0;
        while self.stats.read().unwrap().active_connections > 0 && wait_iterations < 10 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            wait_iterations += 1;
        }
        
        Ok(())
    }
    
    /// Gets the current proxy statistics
    pub fn get_stats(&self) -> ProxyStats {
        self.stats.read().unwrap().clone()
    }
    
    /// Handles an HTTP connection
    #[instrument(skip(stream, url_resolver))]
    async fn handle_http_connection<S>(
        connection_id: Uuid,
        mut stream: S,
        addr: SocketAddr,
        url_resolver: Arc<UrlResolver>,
        enable_access_logging: bool,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Read HTTP request
        let mut buffer = [0; 4096];
        let mut request_size = 0;
        
        // Read initial request data
        loop {
            let n = stream.read(&mut buffer[request_size..]).await?;
            if n == 0 {
                // EOF
                break;
            }
            
            request_size += n;
            
            // Check if we've read the end of the headers
            if request_size >= 4 &&
                buffer[request_size - 4] == b'\r' && buffer[request_size - 3] == b'\n' &&
                buffer[request_size - 2] == b'\r' && buffer[request_size - 1] == b'\n' {
                break;
            }
            
            // Check if the buffer is full
            if request_size == buffer.len() {
                return Err(ProxyError::RequestTooLarge);
            }
        }
        
        if request_size == 0 {
            return Err(ProxyError::EmptyRequest);
        }
        
        // Parse HTTP request line
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        
        let parse_result = req.parse(&buffer[..request_size])
            .map_err(|e| ProxyError::ParseError(format!("Failed to parse HTTP request: {}", e)))?;
        
        // Check if we need more data
        if parse_result.is_partial() {
            return Err(ProxyError::IncompleteRequest);
        }
        
        // Extract request information
        let method = req.method.ok_or_else(|| ProxyError::ParseError("Missing method".to_string()))?;
        let path = req.path.ok_or_else(|| ProxyError::ParseError("Missing path".to_string()))?;
        let version = req.version.ok_or_else(|| ProxyError::ParseError("Missing version".to_string()))?;
        
        // Extract Host header
        let host = req.headers.iter()
            .find(|h| h.name.eq_ignore_ascii_case("Host"))
            .map(|h| std::str::from_utf8(h.value).unwrap_or_default())
            .ok_or_else(|| ProxyError::ParseError("Missing Host header".to_string()))?;
        
        // Construct target URL
        let scheme = "http";
        let url_str = format!("{}://{}{}", scheme, host, path);
        
        if enable_access_logging {
            info!("HTTP {} {} from {}", method, url_str, addr);
        }
        
        // Resolve target instance
        let instance = url_resolver.resolve(&url_str)
            .ok_or_else(|| ProxyError::NoRouteToHost(url_str.clone()))?;
        
        // TODO: Open connection to target instance and proxy data
        // For now, we'll just return a simple response
        
        // Construct response
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: 59\r\n\
             Connection: close\r\n\
             \r\n\
             Request successfully routed to instance {}",
            instance.read().unwrap().id
        );
        
        // Send response
        stream.write_all(response.as_bytes()).await?;
        
        Ok(())
    }
    
    /// Handles an HTTPS connection
    #[instrument(skip(stream, url_resolver))]
    async fn handle_https_connection<S>(
        connection_id: Uuid,
        stream: S,
        addr: SocketAddr,
        url_resolver: Arc<UrlResolver>,
        enable_access_logging: bool,
    ) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // The implementation for HTTPS is similar to HTTP, but with TLS handling
        // For brevity, we'll skip the full implementation here
        Ok(())
    }
    
    /// Performs a health check on all instances
    async fn perform_health_check(url_resolver: Arc<UrlResolver>) {
        // In a real implementation, we would check the health of all instances
        // and update their status in the URL resolver
    }
}

/// Error during proxy operations
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Failed to bind listener: {0}")]
    BindError(String),
    
    #[error("TLS configuration error: {0}")]
    TlsConfigError(String),
    
    #[error("No route to host: {0}")]
    NoRouteToHost(String),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Request too large")]
    RequestTooLarge,
    
    #[error("Empty request")]
    EmptyRequest,
    
    #[error("Incomplete request")]
    IncompleteRequest,
}