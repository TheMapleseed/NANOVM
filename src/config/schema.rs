use serde_json::{json, Value};

/// Get JSON schema for VM configuration validation
pub fn get_vm_config_schema() -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["version", "resources", "security", "network", "scaling", "secrets", "observability"],
        "properties": {
            "version": {
                "type": "string",
                "pattern": "^[0-9]+\\.[0-9]+$"
            },
            "resources": {
                "type": "object",
                "required": ["memory_limit_bytes", "cpu_limit", "timeout_seconds", "storage_limit_bytes"],
                "properties": {
                    "memory_limit_bytes": {
                        "type": "integer",
                        "minimum": 1
                    },
                    "cpu_limit": {
                        "type": "number",
                        "minimum": 0.1
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "minimum": 0
                    },
                    "storage_limit_bytes": {
                        "type": "integer",
                        "minimum": 1
                    }
                }
            },
            "security": {
                "type": "object",
                "required": ["data_guard", "wx_policy", "sandbox"],
                "properties": {
                    "data_guard": {
                        "type": "object",
                        "required": ["enabled"],
                        "properties": {
                            "enabled": {
                                "type": "boolean"
                            },
                            "outbound_network": {
                                "type": ["object", "null"],
                                "properties": {
                                    "allow_outbound": {
                                        "type": "boolean"
                                    },
                                    "allowed_hostnames": {
                                        "type": "array",
                                        "items": {
                                            "type": "string"
                                        }
                                    }
                                }
                            },
                            "filesystem": {
                                "type": ["object", "null"],
                                "properties": {
                                    "allow_filesystem": {
                                        "type": "boolean"
                                    },
                                    "storage_limit_bytes": {
                                        "type": "integer",
                                        "minimum": 1
                                    },
                                    "allowed_paths": {
                                        "type": "array",
                                        "items": {
                                            "type": "string"
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "wx_policy": {
                        "type": "object",
                        "required": ["strict", "audit_logging", "default_protection"],
                        "properties": {
                            "strict": {
                                "type": "boolean"
                            },
                            "audit_logging": {
                                "type": "boolean"
                            },
                            "default_protection": {
                                "type": "string",
                                "enum": ["ReadOnly", "ReadWrite", "Executable"]
                            },
                            "memory_regions": {
                                "type": ["array", "null"],
                                "items": {
                                    "type": "object",
                                    "required": ["name", "base_address", "size_bytes", "protection"],
                                    "properties": {
                                        "name": {
                                            "type": "string"
                                        },
                                        "base_address": {
                                            "type": "integer",
                                            "minimum": 0
                                        },
                                        "size_bytes": {
                                            "type": "integer",
                                            "minimum": 1
                                        },
                                        "protection": {
                                            "type": "string",
                                            "enum": ["ReadOnly", "ReadWrite", "Executable"]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "sandbox": {
                        "type": "object",
                        "required": ["enabled", "allow_syscalls", "allowed_syscalls", "enable_seccomp"],
                        "properties": {
                            "enabled": {
                                "type": "boolean"
                            },
                            "allow_syscalls": {
                                "type": "boolean"
                            },
                            "allowed_syscalls": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                }
                            },
                            "enable_seccomp": {
                                "type": "boolean"
                            }
                        }
                    }
                }
            },
            "network": {
                "type": "object",
                "required": ["urls", "interface", "tls"],
                "properties": {
                    "urls": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "pattern": "^https?://.+"
                        }
                    },
                    "interface": {
                        "type": "object",
                        "required": ["enable_inbound", "enable_outbound", "listen_port", "max_connections", "connection_timeout_seconds"],
                        "properties": {
                            "enable_inbound": {
                                "type": "boolean"
                            },
                            "enable_outbound": {
                                "type": "boolean"
                            },
                            "listen_port": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 65535
                            },
                            "max_connections": {
                                "type": "integer",
                                "minimum": 1
                            },
                            "connection_timeout_seconds": {
                                "type": "integer",
                                "minimum": 1
                            }
                        }
                    },
                    "tls": {
                        "type": "object",
                        "required": ["enabled", "min_version", "enable_mtls", "require_client_cert"],
                        "properties": {
                            "enabled": {
                                "type": "boolean"
                            },
                            "cert_path": {
                                "type": ["string", "null"]
                            },
                            "key_path": {
                                "type": ["string", "null"]
                            },
                            "min_version": {
                                "type": "string",
                                "enum": ["1.0", "1.1", "1.2", "1.3"]
                            },
                            "enable_mtls": {
                                "type": "boolean"
                            },
                            "client_ca_path": {
                                "type": ["string", "null"]
                            },
                            "require_client_cert": {
                                "type": "boolean"
                            }
                        }
                    }
                }
            },
            "scaling": {
                "type": "object",
                "required": ["mirrors", "autoscale", "state_sync"],
                "properties": {
                    "mirrors": {
                        "type": "integer",
                        "minimum": 0
                    },
                    "autoscale": {
                        "type": "object",
                        "required": ["enabled", "min_instances", "max_instances", "cpu_threshold", "cooldown_seconds"],
                        "properties": {
                            "enabled": {
                                "type": "boolean"
                            },
                            "min_instances": {
                                "type": "integer",
                                "minimum": 1
                            },
                            "max_instances": {
                                "type": "integer",
                                "minimum": 1
                            },
                            "cpu_threshold": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100
                            },
                            "cooldown_seconds": {
                                "type": "integer",
                                "minimum": 1
                            }
                        }
                    },
                    "state_sync": {
                        "type": "object",
                        "required": ["sync_interval_ms", "max_delta_size_bytes", "enable_conflict_resolution"],
                        "properties": {
                            "sync_interval_ms": {
                                "type": "integer",
                                "minimum": 1
                            },
                            "max_delta_size_bytes": {
                                "type": "integer",
                                "minimum": 1
                            },
                            "enable_conflict_resolution": {
                                "type": "boolean"
                            }
                        }
                    }
                }
            },
            "secrets": {
                "type": "object",
                "required": ["api_keys", "env_vars"],
                "properties": {
                    "api_keys": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name", "value_from"],
                            "properties": {
                                "name": {
                                    "type": "string"
                                },
                                "value_from": {
                                    "oneOf": [
                                        {
                                            "type": "object",
                                            "required": ["value"],
                                            "properties": {
                                                "value": {
                                                    "type": "string"
                                                }
                                            }
                                        },
                                        {
                                            "type": "object",
                                            "required": ["source"],
                                            "properties": {
                                                "source": {
                                                    "type": "string"
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    },
                    "env_vars": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name", "value_from"],
                            "properties": {
                                "name": {
                                    "type": "string"
                                },
                                "value_from": {
                                    "oneOf": [
                                        {
                                            "type": "object",
                                            "required": ["value"],
                                            "properties": {
                                                "value": {
                                                    "type": "string"
                                                }
                                            }
                                        },
                                        {
                                            "type": "object",
                                            "required": ["source"],
                                            "properties": {
                                                "source": {
                                                    "type": "string"
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            },
            "observability": {
                "type": "object",
                "required": ["metrics", "tracing", "logging"],
                "properties": {
                    "metrics": {
                        "type": "object",
                        "required": ["enabled", "interval_seconds", "exporters"],
                        "properties": {
                            "enabled": {
                                "type": "boolean"
                            },
                            "interval_seconds": {
                                "type": "integer",
                                "minimum": 1
                            },
                            "exporters": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["type", "endpoint", "config"],
                                    "properties": {
                                        "type": {
                                            "type": "string"
                                        },
                                        "endpoint": {
                                            "type": "string"
                                        },
                                        "config": {
                                            "type": "object",
                                            "additionalProperties": {
                                                "type": "string"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "tracing": {
                        "type": "object",
                        "required": ["enabled", "sampling_rate"],
                        "properties": {
                            "enabled": {
                                "type": "boolean"
                            },
                            "sampling_rate": {
                                "type": "number",
                                "minimum": 0.0,
                                "maximum": 1.0
                            },
                            "exporter": {
                                "type": ["object", "null"],
                                "required": ["type", "endpoint", "config"],
                                "properties": {
                                    "type": {
                                        "type": "string"
                                    },
                                    "endpoint": {
                                        "type": "string"
                                    },
                                    "config": {
                                        "type": "object",
                                        "additionalProperties": {
                                            "type": "string"
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "logging": {
                        "type": "object",
                        "required": ["level", "log_to_stdout", "log_to_file", "format"],
                        "properties": {
                            "level": {
                                "type": "string",
                                "enum": ["Error", "Warning", "Info", "Debug", "Trace"]
                            },
                            "log_to_stdout": {
                                "type": "boolean"
                            },
                            "log_to_file": {
                                "type": "boolean"
                            },
                            "log_file": {
                                "type": ["string", "null"]
                            },
                            "format": {
                                "type": "string",
                                "enum": ["Plain", "Json", "Structured"]
                            }
                        }
                    }
                }
            }
        }
    })
}

/// Validate configuration against JSON schema
pub fn validate_config_against_schema(config_json: &Value) -> Result<(), String> {
    let schema = get_vm_config_schema();
    
    // Use the jsonschema crate to validate
    let compiled = jsonschema::JSONSchema::compile(&schema)
        .map_err(|e| format!("Failed to compile schema: {}", e))?;
    
    compiled.validate(config_json)
        .map_err(|errors| {
            let error_msgs: Vec<String> = errors
                .map(|e| format!("{} at {}", e, e.instance_path))
                .collect();
            error_msgs.join(", ")
        })
} 