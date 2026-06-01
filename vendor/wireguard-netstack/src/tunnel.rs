//! High-level managed WireGuard tunnel.
//!
//! This module provides `ManagedTunnel`, a convenient abstraction that handles
//! all the background tasks required to run a WireGuard tunnel.

use crate::error::{Error, Result};
use crate::netstack::NetStack;
use crate::wireguard::{WireGuardConfig, WireGuardTunnel};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

/// A managed WireGuard tunnel that handles all background tasks automatically.
///
/// This is the main entry point for library users. It:
/// - Creates and configures the WireGuard tunnel
/// - Creates the userspace network stack
/// - Spawns all required background tasks
/// - Performs the WireGuard handshake
/// - Provides access to the `NetStack` for making TCP connections
///
/// # Example
///
/// ```no_run
/// use wireguard_netstack::{ManagedTunnel, WgConfigFile};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Load config and connect
///     let config = WgConfigFile::from_file("wg.conf")?
///         .into_wireguard_config()
///         .await?;
///     
///     let tunnel = ManagedTunnel::connect(config).await?;
///     
///     // Use tunnel.netstack() to create TCP connections
///     // ...
///     
///     // Graceful shutdown
///     tunnel.shutdown().await;
///     Ok(())
/// }
/// ```
pub struct ManagedTunnel {
    /// The underlying WireGuard tunnel.
    wg_tunnel: Arc<WireGuardTunnel>,
    /// The userspace network stack.
    netstack: Arc<NetStack>,
    /// Background task handles.
    tasks: JoinSet<()>,
}

impl ManagedTunnel {
    /// Connect to a WireGuard peer using the provided configuration.
    ///
    /// This will:
    /// 1. Create the WireGuard tunnel
    /// 2. Create the userspace network stack
    /// 3. Spawn all background tasks
    /// 4. Initiate and wait for the WireGuard handshake
    ///
    /// # Arguments
    ///
    /// * `config` - WireGuard configuration
    ///
    /// # Returns
    ///
    /// A `ManagedTunnel` ready to use for making TCP connections.
    pub async fn connect(config: WireGuardConfig) -> Result<Self> {
        Self::connect_with_timeout(config, Duration::from_secs(10)).await
    }

    /// Connect with a custom handshake timeout.
    pub async fn connect_with_timeout(
        config: WireGuardConfig,
        handshake_timeout: Duration,
    ) -> Result<Self> {
        log::info!("Creating WireGuard tunnel...");
        let wg_tunnel = WireGuardTunnel::new(config)
            .await
            .map_err(|e| Error::TunnelCreation(e.to_string()))?;

        // Take the incoming receiver before starting tasks
        let incoming_rx = wg_tunnel
            .take_incoming_receiver()
            .ok_or_else(|| Error::TunnelCreation("Failed to get incoming receiver".into()))?;

        // Create the network stack
        log::info!("Creating userspace network stack...");
        let netstack = NetStack::new(wg_tunnel.clone());

        // Spawn background tasks
        log::info!("Starting background tasks...");
        let mut tasks = JoinSet::new();

        // WireGuard receive loop
        let wg = wg_tunnel.clone();
        tasks.spawn(async move {
            if let Err(e) = wg.run_receive_loop().await {
                log::error!("WireGuard receive loop error: {}", e);
            }
        });

        // WireGuard send loop
        let wg = wg_tunnel.clone();
        tasks.spawn(async move {
            if let Err(e) = wg.run_send_loop().await {
                log::error!("WireGuard send loop error: {}", e);
            }
        });

        // WireGuard timer loop
        let wg = wg_tunnel.clone();
        tasks.spawn(async move {
            if let Err(e) = wg.run_timer_loop().await {
                log::error!("WireGuard timer loop error: {}", e);
            }
        });

        // Network stack poll loop
        let ns = netstack.clone();
        tasks.spawn(async move {
            if let Err(e) = ns.run_poll_loop().await {
                log::error!("Network stack poll loop error: {}", e);
            }
        });

        // Network stack RX loop
        let ns = netstack.clone();
        tasks.spawn(async move {
            if let Err(e) = ns.run_rx_loop(incoming_rx).await {
                log::error!("Network stack RX loop error: {}", e);
            }
        });

        // Give tasks time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Initiate handshake
        log::info!("Initiating WireGuard handshake...");
        wg_tunnel
            .initiate_handshake()
            .await
            .map_err(|e| Error::TunnelCreation(e.to_string()))?;

        // Wait for handshake
        log::info!("Waiting for WireGuard handshake to complete...");
        wg_tunnel.wait_for_handshake(handshake_timeout).await?;

        log::info!("WireGuard tunnel established!");

        Ok(Self {
            wg_tunnel,
            netstack,
            tasks,
        })
    }

    /// Get the network stack for creating TCP connections.
    pub fn netstack(&self) -> Arc<NetStack> {
        self.netstack.clone()
    }

    /// Get the underlying WireGuard tunnel.
    pub fn wg_tunnel(&self) -> Arc<WireGuardTunnel> {
        self.wg_tunnel.clone()
    }

    /// Returns the time elapsed since the last successful WireGuard handshake.
    ///
    /// Returns `Some(duration)` if a handshake has completed, or `None` if no
    /// handshake has occurred yet. This is useful for health-checking the tunnel:
    /// WireGuard re-handshakes every ~120s on an active session, so a value
    /// exceeding ~180s typically indicates the tunnel is stale.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use wireguard_netstack::ManagedTunnel;
    ///
    /// fn check_health(tunnel: &ManagedTunnel) -> bool {
    ///     match tunnel.time_since_last_handshake() {
    ///         Some(elapsed) => elapsed < Duration::from_secs(180),
    ///         None => false,
    ///     }
    /// }
    /// ```
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.wg_tunnel.time_since_last_handshake()
    }

    /// Gracefully shutdown the tunnel.
    ///
    /// This aborts all background tasks and waits for them to complete.
    pub async fn shutdown(mut self) {
        log::info!("Shutting down WireGuard tunnel...");
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        log::info!("WireGuard tunnel shutdown complete.");
    }
}

impl Drop for ManagedTunnel {
    fn drop(&mut self) {
        // Abort all tasks on drop
        self.tasks.abort_all();
    }
}
