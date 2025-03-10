// src/security/wx_enforcer.rs

use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

/// Memory region protection status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    /// Read-only memory
    ReadOnly,
    
    /// Read-write memory (no execution)
    ReadWrite,
    
    /// Executable memory (no write)
    Executable,
}

/// Enforces W^X (Write XOR Execute) memory policy
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
    
    /// Registers a memory region with specific protection
    pub fn register_region(
        &self,
        address: usize,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<(), WxError> {
        // Validate no overlapping regions
        let regions = self.memory_regions.read().unwrap();
        for (&addr, &(len, _)) in regions.iter() {
            if (address >= addr && address < addr + len) || 
               (addr >= address && addr < address + size) {
                return Err(WxError::OverlappingRegion);
            }
        }
        
        // Register the new region
        drop(regions);
        self.memory_regions.write().unwrap().insert(address, (size, protection));
        
        // Log the operation
        self.audit_log.write().unwrap().push((
            address,
            format!("register_region(size={}, protection={:?})", size, protection),
            chrono::Utc::now(),
        ));
        
        Ok(())
    }
    
    /// Attempts to change protection of a memory region
    pub fn change_protection(
        &self,
        address: usize,
        protection: MemoryProtection,
    ) -> Result<(), WxError> {
        let mut regions = self.memory_regions.write().unwrap();
        
        // Find the region
        if let Some((size, current_protection)) = regions.get_mut(&address) {
            // Enforce W^X policy
            if *current_protection == MemoryProtection::Executable && 
               protection == MemoryProtection::ReadWrite {
                return Err(WxError::WxViolation);
            }
            
            // Update protection
            *current_protection = protection;
            
            // Log the operation
            self.audit_log.write().unwrap().push((
                address,
                format!("change_protection(from={:?}, to={:?})", current_protection, protection),
                chrono::Utc::now(),
            ));
            
            Ok(())
        } else {
            Err(WxError::RegionNotFound)
        }
    }
    
    /// Validates whether an operation is allowed on a memory region
    pub fn validate_operation(
        &self,
        address: usize,
        is_write: bool,
        is_execute: bool,
    ) -> Result<(), WxError> {
        let regions = self.memory_regions.read().unwrap();
        
        // Find the containing region
        for (&addr, &(size, protection)) in regions.iter() {
            if address >= addr && address < addr + size {
                // Enforce protection
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
                
                return Ok(());
            }
        }
        
        Err(WxError::AddressNotMapped)
    }
}

/// Errors that can occur during W^X enforcement
#[derive(Debug, thiserror::Error)]
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
}