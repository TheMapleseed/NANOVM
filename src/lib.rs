// NanoVM - Enterprise-grade rootless virtualization system
//
// Licensed under the GNU General Public License v3.0

//! NanoVM is an enterprise-grade, rootless virtualization system built in Rust.
//! It provides secure, isolated environments for running applications with 
//! strong security guarantees, comprehensive resource controls, and advanced 
//! networking capabilities.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

/// Configuration subsystem
pub mod config;

/// Virtual machine core
pub mod vm;

/// Network subsystem
pub mod network;

/// Security subsystem
pub mod security;

/// Scaling subsystem
pub mod scaling;

/// Service interface
pub mod service;

/// Sandbox implementation
pub mod sandbox;

/// Execution engine
pub mod execution;

// Re-export common types
pub use config::VmConfig;
pub use service::Service;
pub use vm::instance::Instance; 