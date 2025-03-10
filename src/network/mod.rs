// Network subsystem

pub mod url_resolver;
pub mod proxy;
// pub mod load_balancer;

// Re-exports
pub use url_resolver::UrlResolver;
pub use proxy::{ProxyServer, ProxyConfig}; 