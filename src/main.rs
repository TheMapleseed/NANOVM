use nanovm::config::{ConfigManager, ConfigError};
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::sync::mpsc;
use tracing::{error, info};

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
    
    info!("Starting NanoVM...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    
    // Parse command-line arguments
    let opt = Opt::from_args();
    
    // Load configuration
    info!("Loading configuration from: {}", opt.config.display());
    let mut config_manager = ConfigManager::load_from_file(&opt.config)
        .map_err(|e| {
            error!("Failed to load configuration: {}", e);
            e
        })?;
    
    // Resolve secrets
    config_manager.resolve_secrets()?;
    
    // Get the final configuration
    let config = config_manager.get_config().clone();
    
    // Initialize the service
    info!("Initializing NanoVM service...");
    let service = nanovm::service::Service::new(&opt.config.to_string_lossy()).await?;
    
    // Create a shutdown channel
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    
    // Set up signal handling
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        
        let shutdown_tx_clone = shutdown_tx.clone();
        
        tokio::spawn(async move {
            tokio::select! {
                _ = sigint.recv() => {
                    info!("Received SIGINT, shutting down...");
                    let _ = shutdown_tx_clone.send(()).await;
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, shutting down...");
                    let _ = shutdown_tx_clone.send(()).await;
                }
            }
        });
    }
    
    // Wait for shutdown signal
    shutdown_rx.recv().await;
    
    // Shutdown the service
    info!("Shutting down NanoVM...");
    service.shutdown().await?;
    
    info!("NanoVM has been shut down.");
    Ok(())
} 