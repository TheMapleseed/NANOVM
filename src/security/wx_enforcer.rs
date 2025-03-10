// src/security/wx_enforcer.rs

use std::collections::HashMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, PoisonError};
use thiserror::Error;

/// Memory protection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    /// Read-only memory
    ReadOnly,
    
    /// Read-write memory (no execution)
    ReadWrite,
    
    /// Executable memory (no write)
    Executable,
}

/// Write XOR Execute policy enforcer
pub struct WxEnforcer {
    /// Maps memory regions to their protection status
    memory_regions: RwLock<HashMap<usize, (usize, MemoryProtection)>>,
    
    /// Memory operations audit log (address, operation, timestamp)
    audit_log: RwLock<Vec<(usize, String, chrono::DateTime<chrono::Utc>)>>,
}

impl WxEnforcer {
    /// Creates a new W^X enforcer
    pub fn new() -> Self {
        Self {
            memory_regions: RwLock::new(HashMap::new()),
            audit_log: RwLock::new(Vec::new()),
        }
    }
    
    /// Registers a memory region with protection settings
    pub fn register_region(
        &self,
        address: usize,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<(), WxError> {
        // Check for overlapping regions
        {
            let regions = self.memory_regions.read().map_err(|e| {
                WxError::LockError(format!("Failed to acquire read lock: {}", e))
            })?;
            
            for (&addr, &(region_size, _)) in regions.iter() {
                // Check for overlap
                if (address >= addr && address < addr + region_size) ||
                   (addr >= address && addr < address + size) {
                    return Err(WxError::OverlappingRegion);
                }
            }
        }
        
        // Register the region
        let mut regions = self.memory_regions.write().map_err(|e| {
            WxError::LockError(format!("Failed to acquire write lock: {}", e))
        })?;
        
        regions.insert(address, (size, protection));
        
        // Log the operation
        match self.audit_log.write() {
            Ok(mut log) => {
                log.push((
                    address,
                    format!("register_region(size={}, protection={:?})", size, protection),
                    chrono::Utc::now(),
                ));
            },
            Err(e) => {
                // Just log the error but don't fail the operation
                tracing::warn!("Failed to log memory operation: {}", e);
            }
        }
        
        Ok(())
    }
    
    /// Changes protection mode for a memory region
    pub fn change_protection(
        &self,
        address: usize,
        protection: MemoryProtection,
    ) -> Result<(), WxError> {
        // Find the region
        let mut regions = self.memory_regions.write().map_err(|e| {
            WxError::LockError(format!("Failed to acquire write lock: {}", e))
        })?;
        
        if let Some((_, old_protection)) = regions.get_mut(&address) {
            // Update protection
            *old_protection = protection;
            
            // Log the operation
            match self.audit_log.write() {
                Ok(mut log) => {
                    log.push((
                        address,
                        format!("change_protection(protection={:?})", protection),
                        chrono::Utc::now(),
                    ));
                },
                Err(e) => {
                    // Just log the error but don't fail the operation
                    tracing::warn!("Failed to log memory operation: {}", e);
                }
            }
            
            Ok(())
        } else {
            Err(WxError::RegionNotFound)
        }
    }
    
    /// Validates a memory operation against W^X policy
    pub fn validate_operation(
        &self,
        address: usize,
        is_write: bool,
        is_execute: bool,
    ) -> Result<(), WxError> {
        // Find the region containing this address
        let regions = self.memory_regions.read().map_err(|e| {
            WxError::LockError(format!("Failed to acquire read lock: {}", e))
        })?;
        
        for (&region_addr, &(region_size, protection)) in regions.iter() {
            if address >= region_addr && address < region_addr + region_size {
                // Check operation against protection
                match protection {
                    MemoryProtection::ReadOnly => {
                        if is_write || is_execute {
                            return Err(WxError::ProtectionViolation);
                        }
                    }
                    MemoryProtection::ReadWrite => {
                        if is_execute {
                            return Err(WxError::WxViolation);
                        }
                    }
                    MemoryProtection::Executable => {
                        if is_write {
                            return Err(WxError::WxViolation);
                        }
                    }
                }
                
                // Operation is allowed
                return Ok(());
            }
        }
        
        // Address not mapped
        Err(WxError::AddressNotMapped)
    }
}

/// Error during W^X policy enforcement
#[derive(Error, Debug)]
pub enum WxError {
    #[error("W^X policy violation")]
    WxViolation,
    
    #[error("Memory protection violation")]
    ProtectionViolation,
    
    #[error("Memory region not found")]
    RegionNotFound,
    
    #[error("Memory address not mapped")]
    AddressNotMapped,
    
    #[error("Overlapping memory region")]
    OverlappingRegion,
    
    #[error("Lock error: {0}")]
    LockError(String),
}