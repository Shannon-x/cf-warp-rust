//! WireGuard tunnel implementation using gotatun.
//!
//! This module wraps gotatun's `Tunn` struct and manages the UDP transport
//! for sending/receiving encrypted WireGuard packets.

use bytes::BytesMut;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::Packet;
use gotatun::x25519::{PublicKey, StaticSecret};
use parking_lot::Mutex;
use zerocopy::IntoBytes;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::error::{Error, Result};

/// Configuration for the WireGuard tunnel.
#[derive(Clone)]
pub struct WireGuardConfig {
    /// Our private key (32 bytes).
    pub private_key: [u8; 32],
    /// Peer's public key (32 bytes).
    pub peer_public_key: [u8; 32],
    /// Peer's endpoint (IP:port).
    pub peer_endpoint: SocketAddr,
    /// Our IP address inside the tunnel.
    pub tunnel_ip: Ipv4Addr,
    /// Optional preshared key for additional security.
    pub preshared_key: Option<[u8; 32]>,
    /// Keepalive interval in seconds (0 = disabled).
    pub keepalive_seconds: Option<u16>,
    /// MTU for the tunnel interface (defaults to 460 if None).
    pub mtu: Option<u16>,
}

/// A WireGuard tunnel that encrypts/decrypts IP packets.
pub struct WireGuardTunnel {
    /// The underlying gotatun tunnel.
    tunn: Mutex<Tunn>,
    /// UDP socket for sending/receiving encrypted packets.
    udp_socket: Arc<UdpSocket>,
    /// Peer's endpoint address.
    peer_endpoint: SocketAddr,
    /// Our tunnel IP address.
    tunnel_ip: Ipv4Addr,
    /// MTU for the tunnel interface.
    mtu: u16,
    /// Channel to send received IP packets.
    incoming_tx: mpsc::Sender<BytesMut>,
    /// Channel to receive IP packets to send.
    outgoing_rx: tokio::sync::Mutex<mpsc::Receiver<BytesMut>>,
    /// Channel to receive incoming IP packets.
    incoming_rx: Mutex<Option<mpsc::Receiver<BytesMut>>>,
    /// Channel to send IP packets for encryption.
    outgoing_tx: mpsc::Sender<BytesMut>,
}

impl WireGuardTunnel {
    /// Create a new WireGuard tunnel with the given configuration.
    pub async fn new(config: WireGuardConfig) -> Result<Arc<Self>> {
        // Create the cryptographic keys
        let private_key = StaticSecret::from(config.private_key);
        let peer_public_key = PublicKey::from(config.peer_public_key);

        // Create the tunnel
        let tunn = Tunn::new(
            private_key,
            peer_public_key,
            config.preshared_key,
            config.keepalive_seconds,
            rand::random::<u32>() >> 8, // Random index
            Arc::new(RateLimiter::new(&peer_public_key, 0)),
        );

        // Bind UDP socket to any available port
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;

        // Increase socket receive buffer to avoid packet loss
        let sock_ref = socket2::SockRef::from(&udp_socket);
        if let Err(e) = sock_ref.set_recv_buffer_size(1024 * 1024) {
            // 1MB buffer
            log::warn!("Failed to set UDP recv buffer size: {}", e);
        }
        if let Err(e) = sock_ref.set_send_buffer_size(1024 * 1024) {
            // 1MB buffer
            log::warn!("Failed to set UDP send buffer size: {}", e);
        }
        log::info!("UDP recv buffer size: {:?}", sock_ref.recv_buffer_size());
        log::info!("UDP send buffer size: {:?}", sock_ref.send_buffer_size());

        log::info!(
            "WireGuard UDP socket bound to {}",
            udp_socket.local_addr()?
        );

        // Create channels for packet communication
        // incoming: packets received from the tunnel (decrypted)
        // outgoing: packets to send through the tunnel (to be encrypted)
        let (incoming_tx, incoming_rx) = mpsc::channel(256);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);

        let tunnel = Arc::new(Self {
            tunn: Mutex::new(tunn),
            udp_socket: Arc::new(udp_socket),
            peer_endpoint: config.peer_endpoint,
            tunnel_ip: config.tunnel_ip,
            mtu: config.mtu.unwrap_or(460), // Default MTU
            incoming_tx,
            incoming_rx: Mutex::new(Some(incoming_rx)),
            outgoing_tx,
            outgoing_rx: tokio::sync::Mutex::new(outgoing_rx),
        });

        Ok(tunnel)
    }

    /// Get our tunnel IP address.
    pub fn tunnel_ip(&self) -> Ipv4Addr {
        self.tunnel_ip
    }

    /// Get the MTU for the tunnel.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Get the sender for outgoing packets.
    pub fn outgoing_sender(&self) -> mpsc::Sender<BytesMut> {
        self.outgoing_tx.clone()
    }

    /// Get the receiver for incoming packets (takes ownership of the receiver).
    pub fn take_incoming_receiver(&self) -> Option<mpsc::Receiver<BytesMut>> {
        self.incoming_rx.lock().take()
    }

    /// Returns the time elapsed since the last successful WireGuard handshake.
    ///
    /// Returns `Some(duration)` if a handshake has completed, or `None` if no
    /// handshake has occurred yet. This is useful for health-checking the tunnel:
    /// WireGuard re-handshakes every ~120s on an active session, so a value
    /// exceeding ~180s typically indicates the tunnel is stale.
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        let tunn = self.tunn.lock();
        tunn.stats().0
    }

    /// Initiate the WireGuard handshake.
    pub async fn initiate_handshake(&self) -> Result<()> {
        log::info!("Initiating WireGuard handshake...");

        let handshake_init = {
            let mut tunn = self.tunn.lock();
            tunn.format_handshake_initiation(false)
        };

        if let Some(packet) = handshake_init {
            // Convert Packet<WgHandshakeInit> to bytes
            let data = packet.as_bytes();
            self.udp_socket.send_to(data, self.peer_endpoint).await?;
            log::debug!("Sent handshake initiation ({} bytes)", data.len());
        }

        Ok(())
    }

    /// Send an IP packet through the tunnel (encrypts and sends via UDP).
    pub async fn send_ip_packet(&self, packet: BytesMut) -> Result<()> {
        let encrypted = {
            let mut tunn = self.tunn.lock();
            let pkt = Packet::from_bytes(packet);
            tunn.handle_outgoing_packet(pkt)
        };

        if let Some(wg_packet) = encrypted {
            // Convert WgKind to Packet<[u8]> and get bytes
            let pkt: Packet = wg_packet.into();
            let data = pkt.as_bytes();
            self.udp_socket.send_to(data, self.peer_endpoint).await?;
            log::trace!("Sent encrypted packet ({} bytes)", data.len());
        }

        Ok(())
    }

    /// Process a received UDP packet (decrypts and returns IP packet if any).
    fn process_incoming_udp(&self, data: &[u8]) -> Option<BytesMut> {
        let packet = Packet::from_bytes(BytesMut::from(data));
        let wg_packet = match packet.try_into_wg() {
            Ok(wg) => wg,
            Err(_) => {
                log::warn!("Received non-WireGuard packet");
                return None;
            }
        };

        let mut tunn = self.tunn.lock();
        match tunn.handle_incoming_packet(wg_packet) {
            TunnResult::Done => {
                log::trace!("WG: Packet processed (no output)");
                None
            }
            TunnResult::Err(e) => {
                log::warn!("WG error: {:?}", e);
                None
            }
            TunnResult::WriteToNetwork(response) => {
                log::trace!("WG: Sending response packet");
                // Need to send a response (e.g., handshake response, keepalive)
                let pkt: Packet = response.into();
                let data = BytesMut::from(pkt.as_bytes());
                let socket = self.udp_socket.clone();
                let endpoint = self.peer_endpoint;
                tokio::spawn(async move {
                    if let Err(e) = socket.send_to(&data, endpoint).await {
                        log::error!("Failed to send response: {}", e);
                    }
                });

                // Also try to send any queued packets
                for queued in tunn.get_queued_packets() {
                    let pkt: Packet = queued.into();
                    let data = BytesMut::from(pkt.as_bytes());
                    let socket = self.udp_socket.clone();
                    let endpoint = self.peer_endpoint;
                    tokio::spawn(async move {
                        if let Err(e) = socket.send_to(&data, endpoint).await {
                            log::error!("Failed to send queued packet: {}", e);
                        }
                    });
                }

                None
            }
            TunnResult::WriteToTunnel(decrypted) => {
                if decrypted.is_empty() {
                    log::trace!("WG: Received keepalive");
                    return None;
                }
                let bytes = BytesMut::from(decrypted.as_bytes());
                log::trace!("WG: Decrypted {} bytes", bytes.len());
                Some(bytes)
            }
        }
    }

    /// Run the tunnel's receive loop (listens for UDP packets and decrypts them).
    pub async fn run_receive_loop(self: &Arc<Self>) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        loop {
            match self.udp_socket.recv_from(&mut buf).await {
                Ok((len, from)) => {
                    if from != self.peer_endpoint {
                        log::warn!("Received packet from unknown peer: {}", from);
                        continue;
                    }

                    log::trace!("Received UDP packet ({} bytes) from {}", len, from);

                    if let Some(ip_packet) = self.process_incoming_udp(&buf[..len]) {
                        if self.incoming_tx.send(ip_packet).await.is_err() {
                            log::error!("Incoming channel closed");
                            break;
                        }
                    }
                }
                Err(e) => {
                    log::error!("UDP receive error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Run the tunnel's send loop (encrypts and sends IP packets).
    pub async fn run_send_loop(self: &Arc<Self>) -> Result<()> {
        let mut outgoing_rx = self.outgoing_rx.lock().await;

        while let Some(packet) = outgoing_rx.recv().await {
            if let Err(e) = self.send_ip_packet(packet).await {
                log::error!("Failed to send packet: {}", e);
            }
        }

        Ok(())
    }

    /// Run the tunnel's timer loop (handles keepalives and handshake retries).
    pub async fn run_timer_loop(self: &Arc<Self>) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(250));

        loop {
            interval.tick().await;

            let packets_to_send: Vec<Vec<u8>> = {
                let mut tunn = self.tunn.lock();
                match tunn.update_timers() {
                    Ok(Some(packet)) => {
                        let pkt: Packet = packet.into();
                        vec![pkt.as_bytes().to_vec()]
                    }
                    Ok(None) => vec![],
                    Err(e) => {
                        log::trace!("Timer error (may be normal): {:?}", e);
                        vec![]
                    }
                }
            };

            for packet in packets_to_send {
                if let Err(e) = self.udp_socket.send_to(&packet, self.peer_endpoint).await {
                    log::error!("Failed to send timer packet: {}", e);
                }
            }
        }
    }

    /// Wait for the handshake to complete (with timeout).
    pub async fn wait_for_handshake(&self, timeout_duration: Duration) -> Result<()> {
        let start = std::time::Instant::now();

        loop {
            {
                let tunn = self.tunn.lock();
                // Check if we have an active session - time_since_handshake is Some when session is established
                let (time_since_handshake, _tx_bytes, _rx_bytes, _, _) = tunn.stats();
                if time_since_handshake.is_some() {
                    log::info!("WireGuard handshake completed!");
                    return Ok(());
                }
            }

            if start.elapsed() > timeout_duration {
                return Err(Error::HandshakeTimeout(timeout_duration));
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
