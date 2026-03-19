//! Async connection pool for managing NETCONF sessions to multiple devices.
//!
//! ```text
//! DevicePool
//!   ├── Semaphore(max_connections) — global concurrency limit
//!   ├── devices: HashMap<name, DeviceConfig>
//!   └── connections: HashMap<name, Vec<Client>> — idle pool per device
//!
//!   checkout("spine-01") → PoolGuard(Client) — auto-checkin on drop
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use rustnetconf::pool::{DevicePool, DeviceConfig};
//! use rustnetconf::transport::ssh::SshAuth;
//! use rustnetconf::Datastore;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let pool = DevicePool::builder()
//!     .max_connections(50)
//!     .add_device("spine-01", DeviceConfig {
//!         host: "10.0.0.1:830".into(),
//!         username: "admin".into(),
//!         auth: SshAuth::Password("secret".into()),
//!         vendor: None,
//!     })
//!     .build();
//!
//! let mut conn = pool.checkout("spine-01").await?;
//! let config = conn.get_config(Datastore::Running).await?;
//! // conn auto-returned to pool when dropped
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore, SemaphorePermit};

use crate::client::Client;
use crate::error::NetconfError;
use crate::transport::ssh::SshAuth;
use crate::vendor::VendorProfile;

/// Configuration for a single device in the pool.
pub struct DeviceConfig {
    /// Device address in `host:port` or `host` format (default port 830).
    pub host: String,
    /// SSH username.
    pub username: String,
    /// SSH authentication method.
    pub auth: SshAuth,
    /// Optional explicit vendor profile. `None` = auto-detect.
    pub vendor: Option<Box<dyn VendorProfile>>,
}

/// Builder for constructing a `DevicePool`.
pub struct DevicePoolBuilder {
    devices: HashMap<String, DeviceConfig>,
    max_connections: usize,
    checkout_timeout: Duration,
}

impl DevicePoolBuilder {
    /// Set the maximum number of concurrent connections across all devices.
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the timeout for checking out a connection.
    ///
    /// If all connections are in use and none become available within this
    /// duration, `checkout()` returns an error instead of blocking forever.
    pub fn checkout_timeout(mut self, timeout: Duration) -> Self {
        self.checkout_timeout = timeout;
        self
    }

    /// Add a device to the pool.
    pub fn add_device(mut self, name: &str, config: DeviceConfig) -> Self {
        self.devices.insert(name.to_string(), config);
        self
    }

    /// Build the pool.
    pub fn build(self) -> DevicePool {
        DevicePool {
            devices: Arc::new(self.devices),
            semaphore: Arc::new(Semaphore::new(self.max_connections)),
            connections: Arc::new(Mutex::new(HashMap::new())),
            checkout_timeout: self.checkout_timeout,
        }
    }
}

/// Async connection pool for multi-device NETCONF operations.
pub struct DevicePool {
    devices: Arc<HashMap<String, DeviceConfig>>,
    semaphore: Arc<Semaphore>,
    connections: Arc<Mutex<HashMap<String, Vec<Client>>>>,
    checkout_timeout: Duration,
}

impl DevicePool {
    /// Create a new pool builder.
    pub fn builder() -> DevicePoolBuilder {
        DevicePoolBuilder {
            devices: HashMap::new(),
            max_connections: 10,
            checkout_timeout: Duration::from_secs(30),
        }
    }

    /// Check out a connection to a named device.
    ///
    /// Returns a `PoolGuard` that dereferences to `Client` and automatically
    /// returns the connection to the pool when dropped (if still healthy).
    ///
    /// Blocks until a semaphore permit is available, up to `checkout_timeout`.
    pub async fn checkout(&self, device_name: &str) -> Result<PoolGuard<'_>, NetconfError> {
        let config = self.devices.get(device_name).ok_or_else(|| {
            crate::error::TransportError::Connect(format!(
                "unknown device in pool: '{device_name}'"
            ))
        })?;

        // Acquire semaphore permit with timeout
        let permit = tokio::time::timeout(self.checkout_timeout, self.semaphore.acquire())
            .await
            .map_err(|_| {
                crate::error::TransportError::Connect(format!(
                    "pool checkout timeout after {:?} — all connections in use",
                    self.checkout_timeout,
                ))
            })?
            .map_err(|_| {
                crate::error::TransportError::Connect("pool semaphore closed".to_string())
            })?;

        // Try to reuse an idle connection
        {
            let mut conns = self.connections.lock().await;
            if let Some(pool) = conns.get_mut(device_name) {
                if let Some(client) = pool.pop() {
                    return Ok(PoolGuard {
                        client: Some(client),
                        device_name: device_name.to_string(),
                        connections: Arc::clone(&self.connections),
                        _permit: permit,
                    });
                }
            }
        }

        // No idle connection — create a new one
        let client = connect_device(config).await?;

        Ok(PoolGuard {
            client: Some(client),
            device_name: device_name.to_string(),
            connections: Arc::clone(&self.connections),
            _permit: permit,
        })
    }

    /// Get the names of all devices in the pool.
    pub fn device_names(&self) -> Vec<String> {
        self.devices.keys().cloned().collect()
    }

    /// Get the number of available semaphore permits.
    pub fn available_connections(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// A checked-out connection from the pool.
///
/// Dereferences to `Client` for direct use. Automatically returns the
/// connection to the pool when dropped (if the session is still alive).
/// Broken sessions are discarded.
pub struct PoolGuard<'a> {
    client: Option<Client>,
    device_name: String,
    connections: Arc<Mutex<HashMap<String, Vec<Client>>>>,
    _permit: SemaphorePermit<'a>,
}

impl<'a> PoolGuard<'a> {
    /// Mark the connection as broken — it will be discarded on drop.
    pub fn discard(&mut self) {
        self.client = None;
    }
}

impl<'a> Deref for PoolGuard<'a> {
    type Target = Client;

    fn deref(&self) -> &Client {
        self.client.as_ref().expect("PoolGuard client already taken")
    }
}

impl<'a> DerefMut for PoolGuard<'a> {
    fn deref_mut(&mut self) -> &mut Client {
        self.client.as_mut().expect("PoolGuard client already taken")
    }
}

impl<'a> Drop for PoolGuard<'a> {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            let connections = Arc::clone(&self.connections);
            let device_name = self.device_name.clone();

            tokio::spawn(async move {
                let mut conns = connections.lock().await;
                conns.entry(device_name).or_default().push(client);
            });
        }
        // Semaphore permit released when _permit drops
    }
}

/// Connect to a device using its config.
async fn connect_device(config: &DeviceConfig) -> Result<Client, NetconfError> {
    let mut builder = Client::connect(&config.host).username(&config.username);

    match &config.auth {
        SshAuth::Password(pass) => {
            builder = builder.password(pass);
        }
        SshAuth::KeyFile { path, passphrase } => {
            builder = builder.key_file(path);
            if let Some(pass) = passphrase {
                builder = builder.key_passphrase(pass);
            }
        }
        SshAuth::Agent => {
            builder = builder.ssh_agent();
        }
    }

    builder.connect().await
}
