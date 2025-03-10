// src/execution/mod.rs

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use crate::config::ResourceConfig;
use crate::security::wx_enforcer::WxEnforcer;

/// The maximum number of concurrent tasks that can be executed across all instances
const MAX_GLOBAL_CONCURRENT_TASKS: usize = 10_000;

/// The default number of worker threads to spawn for the execution engine
const DEFAULT_WORKER_THREADS: usize = 32;

/// The maximum queue depth for pending tasks before backpressure is applied
const MAX_TASK_QUEUE_DEPTH: usize = 100_000;

/// Execution priority levels for tasks
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecutionPriority {
    /// Critical system-level tasks that must complete even under load
    Critical = 0,
    
    /// High-priority tasks that should be processed before normal tasks
    High = 1,
    
    /// Normal application-level tasks
    Normal = 2,
    
    /// Low-priority background tasks
    Low = 3,
}

/// Task execution context containing metadata and resources
#[derive(Debug)]
pub struct ExecutionContext {
    /// Unique identifier for this execution context
    pub id: Uuid,
    
    /// Instance ID this context belongs to
    pub instance_id: Uuid,
    
    /// Time when this context was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    
    /// Execution priority
    pub priority: ExecutionPriority,
    
    /// Resource limits for this execution
    pub resource_limits: ResourceLimits,
    
    /// Security context for execution
    pub security_context: Arc<SecurityContext>,
    
    /// Additional attributes for this execution
    pub attributes: std::collections::HashMap<String, String>,
    
    /// Cancellation channel
    cancel_tx: Option<oneshot::Sender<()>>,
    
    /// Task completion channel
    completion_tx: Option<oneshot::Sender<ExecutionResult>>,
}

/// Resource limits for a task execution
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum memory usage in bytes
    pub memory_limit_bytes: u64,
    
    /// Maximum CPU time in milliseconds
    pub cpu_time_limit_ms: u64,
    
    /// Maximum wall-clock execution time in milliseconds
    pub execution_time_limit_ms: u64,
    
    /// Maximum number of I/O operations
    pub io_operation_limit: u64,
}

/// Security context for task execution
#[derive(Debug)]
pub struct SecurityContext {
    /// Memory protection enforcer
    pub wx_enforcer: Arc<WxEnforcer>,
    
    /// Allowed operation mask (bitfield of allowed operations)
    pub allowed_operations: u64,
    
    /// Namespace isolation ID
    pub namespace_id: Uuid,
}

/// Result of an execution
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Execution context ID
    pub context_id: Uuid,
    
    /// Success or failure status
    pub status: ExecutionStatus,
    
    /// Output data (if any)
    pub output: Option<Vec<u8>>,
    
    /// Execution statistics
    pub stats: ExecutionStats,
    
    /// Error details (if any)
    pub error: Option<ExecutionError>,
}

/// Execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Execution completed successfully
    Success,
    
    /// Execution failed with an error
    Failed,
    
    /// Execution was cancelled
    Cancelled,
    
    /// Execution timed out
    TimedOut,
    
    /// Execution violated resource limits
    ResourceLimitViolation,
    
    /// Execution violated security constraints
    SecurityViolation,
}

/// Execution statistics
#[derive(Debug, Clone)]
pub struct ExecutionStats {
    /// Total execution time in milliseconds
    pub execution_time_ms: u64,
    
    /// CPU time used in milliseconds
    pub cpu_time_ms: u64,
    
    /// Memory usage in bytes
    pub memory_used_bytes: u64,
    
    /// Number of I/O operations performed
    pub io_operations: u64,
    
    /// Number of syscalls performed
    pub syscalls: u64,
}

/// Execution error details
#[derive(Debug, Clone)]
pub struct ExecutionError {
    /// Error code
    pub code: u32,
    
    /// Error message
    pub message: String,
    
    /// Detailed error information
    pub details: Option<String>,
    
    /// Stack trace (if available)
    pub stack_trace: Option<String>,
}

/// Global execution engine that schedules and executes tasks
pub struct ExecutionEngine {
    /// Unique identifier for this engine
    id: Uuid,
    
    /// Global semaphore for limiting concurrent tasks
    global_semaphore: Arc<Semaphore>,
    
    /// Task submission channel
    task_tx: mpsc::Sender<ExecutionTask>,
    
    /// Handle to the runtime
    runtime: tokio::runtime::Handle,
    
    /// Resource monitor
    resource_monitor: Arc<ResourceMonitor>,
    
    /// Active execution contexts
    active_contexts: Arc<RwLock<std::collections::HashMap<Uuid, ExecutionContext>>>,
    
    /// Statistics for this engine
    stats: Arc<RwLock<EngineStats>>,
}

/// Task to be executed
struct ExecutionTask {
    /// Execution context
    context: ExecutionContext,
    
    /// Task function
    task: Pin<Box<dyn Future<Output = Result<Vec<u8>, ExecutionError>> + Send>>,
    
    /// Completion channel
    completion_tx: oneshot::Sender<ExecutionResult>,
}

/// Resource monitor for tracking and limiting resource usage
#[derive(Debug)]
struct ResourceMonitor {
    /// Current memory usage in bytes
    memory_usage: RwLock<u64>,
    
    /// Current CPU usage (percentage * 100)
    cpu_usage: RwLock<u32>,
    
    /// Memory limit exceeded channel
    memory_exceeded_tx: mpsc::Sender<Uuid>,
    
    /// CPU limit exceeded channel
    cpu_exceeded_tx: mpsc::Sender<Uuid>,
    
    /// Resource usage by context ID
    context_usage: RwLock<std::collections::HashMap<Uuid, ResourceUsage>>,
}

/// Resource usage for a specific context
#[derive(Debug, Clone)]
struct ResourceUsage {
    /// Memory usage in bytes
    memory_bytes: u64,
    
    /// CPU time used in milliseconds
    cpu_time_ms: u64,
    
    /// Start time of execution
    start_time: chrono::DateTime<chrono::Utc>,
    
    /// I/O operations count
    io_operations: u64,
}

/// Engine statistics
#[derive(Debug, Clone)]
struct EngineStats {
    /// Total tasks executed
    tasks_executed: u64,
    
    /// Tasks completed successfully
    tasks_succeeded: u64,
    
    /// Tasks failed
    tasks_failed: u64,
    
    /// Tasks cancelled
    tasks_cancelled: u64,
    
    /// Tasks timed out
    tasks_timed_out: u64,
    
    /// Resource limit violations
    resource_violations: u64,
    
    /// Security violations
    security_violations: u64,
    
    /// Total CPU time used in milliseconds
    total_cpu_time_ms: u64,
    
    /// Peak memory usage in bytes
    peak_memory_bytes: u64,
    
    /// Current active tasks
    active_tasks: u64,
    
    /// Current queue depth
    queue_depth: u64,
}

impl ExecutionEngine {
    /// Creates a new execution engine with the specified configuration
    pub fn new(config: &ResourceConfig) -> Result<Self, EngineBuildError> {
        // Create channels
        let (task_tx, mut task_rx) = mpsc::channel::<ExecutionTask>(MAX_TASK_QUEUE_DEPTH);
        let (memory_exceeded_tx, mut memory_exceeded_rx) = mpsc::channel::<Uuid>(1000);
        let (cpu_exceeded_tx, mut cpu_exceeded_rx) = mpsc::channel::<Uuid>(1000);
        
        // Create semaphore for limiting concurrent tasks
        let global_semaphore = Arc::new(Semaphore::new(MAX_GLOBAL_CONCURRENT_TASKS));
        
        // Create resource monitor
        let resource_monitor = Arc::new(ResourceMonitor {
            memory_usage: RwLock::new(0),
            cpu_usage: RwLock::new(0),
            memory_exceeded_tx,
            cpu_exceeded_tx,
            context_usage: RwLock::new(std::collections::HashMap::new()),
        });
        
        // Create active contexts map
        let active_contexts = Arc::new(RwLock::new(std::collections::HashMap::new()));
        
        // Create statistics
        let stats = Arc::new(RwLock::new(EngineStats {
            tasks_executed: 0,
            tasks_succeeded: 0,
            tasks_failed: 0,
            tasks_cancelled: 0,
            tasks_timed_out: 0,
            resource_violations: 0,
            security_violations: 0,
            total_cpu_time_ms: 0,
            peak_memory_bytes: 0,
            active_tasks: 0,
            queue_depth: 0,
        }));
        
        // Get handle to the runtime
        let runtime = tokio::runtime::Handle::current();
        
        // Create the engine
        let engine = Self {
            id: Uuid::new_v4(),
            global_semaphore,
            task_tx,
            runtime,
            resource_monitor: resource_monitor.clone(),
            active_contexts: active_contexts.clone(),
            stats: stats.clone(),
        };
        
        // Clone references for the task processor
        let global_semaphore_clone = engine.global_semaphore.clone();
        let resource_monitor_clone = resource_monitor.clone();
        let active_contexts_clone = active_contexts.clone();
        let stats_clone = stats.clone();
        
        // Spawn task processor
        tokio::spawn(async move {
            info!("Execution engine task processor started");
            
            while let Some(task) = task_rx.recv().await {
                // Update queue depth
                {
                    let mut stats = stats_clone.write().unwrap();
                    stats.queue_depth = task_rx.capacity().unwrap_or(0) as u64;
                }
                
                // Get a permit from the semaphore
                let permit = match global_semaphore_clone.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(e) => {
                        error!("Failed to acquire semaphore permit: {}", e);
                        continue;
                    }
                };
                
                // Register the context as active
                {
                    let mut contexts = active_contexts_clone.write().unwrap();
                    contexts.insert(task.context.id, task.context.clone());
                    
                    let mut stats = stats_clone.write().unwrap();
                    stats.active_tasks += 1;
                    stats.tasks_executed += 1;
                }
                
                // Initialize resource usage tracking
                {
                    let mut context_usage = resource_monitor_clone.context_usage.write().unwrap();
                    context_usage.insert(task.context.id, ResourceUsage {
                        memory_bytes: 0,
                        cpu_time_ms: 0,
                        start_time: chrono::Utc::now(),
                        io_operations: 0,
                    });
                }
                
                // Create cancellation channel
                let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
                
                // Store cancellation channel in context
                {
                    let mut contexts = active_contexts_clone.write().unwrap();
                    if let Some(context) = contexts.get_mut(&task.context.id) {
                        context.cancel_tx = Some(cancel_tx);
                    }
                }
                
                // Clone references for the task execution
                let context_id = task.context.id;
                let resource_limits = task.context.resource_limits.clone();
                let resource_monitor = resource_monitor_clone.clone();
                let active_contexts = active_contexts_clone.clone();
                let stats = stats_clone.clone();
                let completion_tx = task.completion_tx;
                
                // Spawn the task execution
                tokio::spawn(async move {
                    let execution_start = std::time::Instant::now();
                    let result: ExecutionResult;
                    
                    // Create a timeout future
                    let timeout_duration = std::time::Duration::from_millis(
                        resource_limits.execution_time_limit_ms
                    );
                    
                    // Execute the task with timeout and cancellation
                    let task_with_cancel = tokio::select! {
                        biased;
                        
                        // Handle cancellation first
                        _ = cancel_rx => {
                            result = ExecutionResult {
                                context_id,
                                status: ExecutionStatus::Cancelled,
                                output: None,
                                stats: ExecutionStats {
                                    execution_time_ms: execution_start.elapsed().as_millis() as u64,
                                    cpu_time_ms: 0,
                                    memory_used_bytes: 0,
                                    io_operations: 0,
                                    syscalls: 0,
                                },
                                error: Some(ExecutionError {
                                    code: 1,
                                    message: "Task cancelled".to_string(),
                                    details: None,
                                    stack_trace: None,
                                }),
                            };
                            
                            {
                                let mut stats = stats.write().unwrap();
                                stats.tasks_cancelled += 1;
                                stats.active_tasks -= 1;
                            }
                            
                            Ok(result)
                        }
                        
                        // Execute the task with a timeout
                        task_result = tokio::time::timeout(timeout_duration, task.task) => {
                            match task_result {
                                Ok(inner_result) => {
                                    match inner_result {
                                        Ok(output) => {
                                            // Task completed successfully
                                            let execution_time = execution_start.elapsed();
                                            let memory_used;
                                            let cpu_time;
                                            let io_ops;
                                            
                                            // Get resource usage
                                            {
                                                let context_usage = resource_monitor.context_usage.read().unwrap();
                                                let usage = context_usage.get(&context_id)
                                                    .expect("Context usage should exist");
                                                
                                                memory_used = usage.memory_bytes;
                                                cpu_time = usage.cpu_time_ms;
                                                io_ops = usage.io_operations;
                                            }
                                            
                                            // Create execution result
                                            result = ExecutionResult {
                                                context_id,
                                                status: ExecutionStatus::Success,
                                                output: Some(output),
                                                stats: ExecutionStats {
                                                    execution_time_ms: execution_time.as_millis() as u64,
                                                    cpu_time_ms: cpu_time,
                                                    memory_used_bytes: memory_used,
                                                    io_operations: io_ops,
                                                    syscalls: 0,  // TODO: Implement syscall tracking
                                                },
                                                error: None,
                                            };
                                            
                                            {
                                                let mut stats = stats.write().unwrap();
                                                stats.tasks_succeeded += 1;
                                                stats.active_tasks -= 1;
                                                stats.total_cpu_time_ms += cpu_time;
                                                stats.peak_memory_bytes = stats.peak_memory_bytes.max(memory_used);
                                            }
                                            
                                            Ok(result)
                                        }
                                        Err(error) => {
                                            // Task failed with an error
                                            let execution_time = execution_start.elapsed();
                                            
                                            result = ExecutionResult {
                                                context_id,
                                                status: ExecutionStatus::Failed,
                                                output: None,
                                                stats: ExecutionStats {
                                                    execution_time_ms: execution_time.as_millis() as u64,
                                                    cpu_time_ms: 0,  // TODO: Get actual CPU time
                                                    memory_used_bytes: 0,  // TODO: Get actual memory usage
                                                    io_operations: 0,  // TODO: Get actual I/O operations
                                                    syscalls: 0,  // TODO: Get actual syscall count
                                                },
                                                error: Some(error),
                                            };
                                            
                                            {
                                                let mut stats = stats.write().unwrap();
                                                stats.tasks_failed += 1;
                                                stats.active_tasks -= 1;
                                            }
                                            
                                            Ok(result)
                                        }
                                    }
                                }
                                Err(_) => {
                                    // Task timed out
                                    let execution_time = execution_start.elapsed();
                                    
                                    result = ExecutionResult {
                                        context_id,
                                        status: ExecutionStatus::TimedOut,
                                        output: None,
                                        stats: ExecutionStats {
                                            execution_time_ms: execution_time.as_millis() as u64,
                                            cpu_time_ms: 0,  // TODO: Get actual CPU time
                                            memory_used_bytes: 0,  // TODO: Get actual memory usage
                                            io_operations: 0,  // TODO: Get actual I/O operations
                                            syscalls: 0,  // TODO: Get actual syscall count
                                        },
                                        error: Some(ExecutionError {
                                            code: 2,
                                            message: "Task timed out".to_string(),
                                            details: Some(format!("Exceeded timeout of {} ms", resource_limits.execution_time_limit_ms)),
                                            stack_trace: None,
                                        }),
                                    };
                                    
                                    {
                                        let mut stats = stats.write().unwrap();
                                        stats.tasks_timed_out += 1;
                                        stats.active_tasks -= 1;
                                    }
                                    
                                    Ok(result)
                                }
                            }
                        }
                    };
                    
                    // Clean up resources
                    {
                        let mut contexts = active_contexts.write().unwrap();
                        contexts.remove(&context_id);
                        
                        let mut context_usage = resource_monitor.context_usage.write().unwrap();
                        context_usage.remove(&context_id);
                    }
                    
                    // Send the result to the completion channel
                    match task_with_cancel {
                        Ok(result) => {
                            if let Err(e) = completion_tx.send(result) {
                                error!("Failed to send task completion result: {:?}", e);
                            }
                        }
                        Err(e) => {
                            error!("Task execution failed: {:?}", e);
                        }
                    }
                    
                    // Release the semaphore permit
                    drop(permit);
                });
            }
            
            info!("Execution engine task processor stopped");
        });
        
        // Spawn memory limit monitor
        let active_contexts_clone = active_contexts.clone();
        tokio::spawn(async move {
            info!("Memory limit monitor started");
            
            while let Some(context_id) = memory_exceeded_rx.recv().await {
                warn!("Memory limit exceeded for context {}", context_id);
                
                // Cancel the task
                {
                    let mut contexts = active_contexts_clone.write().unwrap();
                    if let Some(context) = contexts.get_mut(&context_id) {
                        if let Some(cancel_tx) = context.cancel_tx.take() {
                            if let Err(e) = cancel_tx.send(()) {
                                error!("Failed to send cancellation signal: {:?}", e);
                            }
                        }
                    }
                }
            }
        });
        
        Ok(engine)
    }
    
    /// Submits a task for execution
    pub async fn submit<F, Fut, T, E>(&self, 
        instance_id: Uuid, 
        priority: ExecutionPriority, 
        resource_limits: ResourceLimits, 
        security_context: Arc<SecurityContext>,
        task_fn: F
    ) -> Result<ExecutionResult, SubmitError>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: Into<Vec<u8>> + Send + 'static,
        E: Into<ExecutionError> + Send + 'static,
    {
        // Create execution context
        let context_id = Uuid::new_v4();
        let context = ExecutionContext {
            id: context_id,
            instance_id,
            created_at: chrono::Utc::now(),
            priority,
            resource_limits: resource_limits.clone(),
            security_context,
            attributes: std::collections::HashMap::new(),
            cancel_tx: None,
            completion_tx: None,
        };
        
        // Create completion channel
        let (completion_tx, completion_rx) = oneshot::channel();
        
        // Wrap the task function
        let task = Box::pin(async move {
            match task_fn().await {
                Ok(result) => Ok(result.into()),
                Err(error) => Err(error.into()),
            }
        });
        
        // Create the execution task
        let execution_task = ExecutionTask {
            context,
            task,
            completion_tx,
        };
        
        // Submit the task
        self.task_tx.send(execution_task).await
            .map_err(|_| SubmitError::TaskChannelClosed)?;
        
        // Wait for the result
        let result = completion_rx.await
            .map_err(|_| SubmitError::ResultChannelClosed)?;
        
        Ok(result)
    }
    
    /// Cancels a task execution
    pub async fn cancel(&self, context_id: Uuid) -> Result<(), CancelError> {
        let mut contexts = self.active_contexts.write().unwrap();
        
        if let Some(context) = contexts.get_mut(&context_id) {
            if let Some(cancel_tx) = context.cancel_tx.take() {
                if let Err(_) = cancel_tx.send(()) {
                    return Err(CancelError::SendFailed);
                }
                
                return Ok(());
            } else {
                return Err(CancelError::AlreadyCancelled);
            }
        }
        
        Err(CancelError::ContextNotFound)
    }
    
    /// Gets the current execution engine statistics
    pub fn get_stats(&self) -> EngineStats {
        self.stats.read().unwrap().clone()
    }
    
    /// Gets the list of active execution contexts
    pub fn get_active_contexts(&self) -> Vec<Uuid> {
        let contexts = self.active_contexts.read().unwrap();
        contexts.keys().cloned().collect()
    }
    
    /// Records memory allocation for a context
    pub fn record_memory_allocation(&self, context_id: Uuid, size: usize) -> Result<(), ResourceError> {
        let mut context_usage = self.resource_monitor.context_usage.write().unwrap();
        
        if let Some(usage) = context_usage.get_mut(&context_id) {
            // Check memory limit
            let new_usage = usage.memory_bytes.saturating_add(size as u64);
            
            // Check if we exceed the limit
            let contexts = self.active_contexts.read().unwrap();
            if let Some(context) = contexts.get(&context_id) {
                if new_usage > context.resource_limits.memory_limit_bytes {
                    // Send limit exceeded notification
                    if let Err(e) = self.resource_monitor.memory_exceeded_tx.try_send(context_id) {
                        warn!("Failed to send memory exceeded notification: {:?}", e);
                    }
                    
                    // Update statistics
                    {
                        let mut stats = self.stats.write().unwrap();
                        stats.resource_violations += 1;
                    }
                    
                    return Err(ResourceError::MemoryLimitExceeded {
                        limit: context.resource_limits.memory_limit_bytes,
                        requested: new_usage,
                    });
                }
            }
            
            // Update usage
            usage.memory_bytes = new_usage;
            
            // Update global memory usage
            {
                let mut memory_usage = self.resource_monitor.memory_usage.write().unwrap();
                *memory_usage = memory_usage.saturating_add(size as u64);
            }
            
            Ok(())
        } else {
            Err(ResourceError::ContextNotFound)
        }
    }
    
    /// Records memory deallocation for a context
    pub fn record_memory_deallocation(&self, context_id: Uuid, size: usize) -> Result<(), ResourceError> {
        let mut context_usage = self.resource_monitor.context_usage.write().unwrap();
        
        if let Some(usage) = context_usage.get_mut(&context_id) {
            // Update usage
            usage.memory_bytes = usage.memory_bytes.saturating_sub(size as u64);
            
            // Update global memory usage
            {
                let mut memory_usage = self.resource_monitor.memory_usage.write().unwrap();
                *memory_usage = memory_usage.saturating_sub(size as u64);
            }
            
            Ok(())
        } else {
            Err(ResourceError::ContextNotFound)
        }
    }
    
    /// Records CPU time for a context
    pub fn record_cpu_time(&self, context_id: Uuid, time_ms: u64) -> Result<(), ResourceError> {
        let mut context_usage = self.resource_monitor.context_usage.write().unwrap();
        
        if let Some(usage) = context_usage.get_mut(&context_id) {
            // Update usage
            usage.cpu_time_ms = usage.cpu_time_ms.saturating_add(time_ms);
            
            // Check CPU time limit
            let contexts = self.active_contexts.read().unwrap();
            if let Some(context) = contexts.get(&context_id) {
                if usage.cpu_time_ms > context.resource_limits.cpu_time_limit_ms {
                    // Send limit exceeded notification
                    if let Err(e) = self.resource_monitor.cpu_exceeded_tx.try_send(context_id) {
                        warn!("Failed to send CPU time exceeded notification: {:?}", e);
                    }
                    
                    // Update statistics
                    {
                        let mut stats = self.stats.write().unwrap();
                        stats.resource_violations += 1;
                    }
                    
                    return Err(ResourceError::CpuTimeLimitExceeded {
                        limit: context.resource_limits.cpu_time_limit_ms,
                        used: usage.cpu_time_ms,
                    });
                }
            }
            
            // Update global CPU usage
            {
                let mut stats = self.stats.write().unwrap();
                stats.total_cpu_time_ms = stats.total_cpu_time_ms.saturating_add(time_ms);
            }
            
            Ok(())
        } else {
            Err(ResourceError::ContextNotFound)
        }
    }
    
    /// Records I/O operation for a context
    pub fn record_io_operation(&self, context_id: Uuid, count: u64) -> Result<(), ResourceError> {
        let mut context_usage = self.resource_monitor.context_usage.write().unwrap();
        
        if let Some(usage) = context_usage.get_mut(&context_id) {
            // Update usage
            usage.io_operations = usage.io_operations.saturating_add(count);
            
            // Check I/O operation limit
            let contexts = self.active_contexts.read().unwrap();
            if let Some(context) = contexts.get(&context_id) {
                if usage.io_operations > context.resource_limits.io_operation_limit {
                    // Update statistics
                    {
                        let mut stats = self.stats.write().unwrap();
                        stats.resource_violations += 1;
                    }
                    
                    return Err(ResourceError::IoOperationLimitExceeded {
                        limit: context.resource_limits.io_operation_limit,
                        used: usage.io_operations,
                    });
                }
            }
            
            Ok(())
        } else {
            Err(ResourceError::ContextNotFound)
        }
    }
}

/// Error during execution engine construction
#[derive(Debug, thiserror::Error)]
pub enum EngineBuildError {
    #[error("Failed to create runtime: {0}")]
    RuntimeCreationFailed(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    
    #[error("Resource allocation failed: {0}")]
    ResourceAllocationFailed(String),
}

/// Error during task submission
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("Task channel closed")]
    TaskChannelClosed,
    
    #[error("Result channel closed")]
    ResultChannelClosed,
    
    #[error("Invalid task")]
    InvalidTask,
    
    #[error("Resource limits exceeded")]
    ResourceLimitsExceeded,
}

/// Error during task cancellation
#[derive(Debug, thiserror::Error)]
pub enum CancelError {
    #[error("Context not found")]
    ContextNotFound,
    
    #[error("Already cancelled")]
    AlreadyCancelled,
    
    #[error("Send failed")]
    SendFailed,
}

/// Error during resource management
#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("Context not found")]
    ContextNotFound,
    
    #[error("Memory limit exceeded (limit: {limit}, requested: {requested})")]
    MemoryLimitExceeded {
        limit: u64,
        requested: u64,
    },
    
    #[error("CPU time limit exceeded (limit: {limit}, used: {used})")]
    CpuTimeLimitExceeded {
        limit: u64,
        used: u64,
    },
    
    #[error("I/O operation limit exceeded (limit: {limit}, used: {used})")]
    IoOperationLimitExceeded {
        limit: u64,
        used: u64,
    },
}

// Implement conversion from execution engine priority to Tokio task priority
impl From<ExecutionPriority> for tokio::task::Priority {
    fn from(priority: ExecutionPriority) -> Self {
        match priority {
            ExecutionPriority::Critical => tokio::task::Priority::HIGH,
            ExecutionPriority::High => tokio::task::Priority::HIGH,
            ExecutionPriority::Normal => tokio::task::Priority::NORMAL,
            ExecutionPriority::Low => tokio::task::Priority::LOW,
        }
    }
}