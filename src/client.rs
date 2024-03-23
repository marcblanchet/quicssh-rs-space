// #![cfg(feature = "rustls")]

use clap::Parser;
use quinn::{ClientConfig, Endpoint, VarInt};
use std::{error::Error, net::SocketAddr, net::ToSocketAddrs, sync::Arc};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(not(windows))]
use tokio::signal::unix::{signal, SignalKind};
#[cfg(windows)]
use tokio::signal::windows::ctrl_c;
use url::Url;

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, Level};

#[derive(Parser, Debug)]
#[clap(name = "client")]
pub struct Opt {
    /// Server address
    url: Url,
    /// Client address
    #[clap(long = "bind", short = 'b')]
    bind_addr: Option<SocketAddr>,

    // sets many transport config parameters to very large values (such as ::MAX) to handle
    // deep space usage, where delays and disruptions can be in order of minutes, hours, days
    #[clap(long = "dtn")]
    dtn: bool,
}

/// Enables MTUD if supported by the operating system
//#[cfg(not(any(windows, os = "linux")))]
pub fn enable_mtud_if_supported() -> quinn::TransportConfig {
    quinn::TransportConfig::default()
}

/// Enables MTUD if supported by the operating system
#[cfg(any(windows, os = "linux"))]
pub fn enable_mtud_if_supported() -> quinn::TransportConfig {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    transport_config
}

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn configure_client(dtnoption: bool) -> Result<ClientConfig, Box<dyn Error>> {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    let mut client_config = ClientConfig::new(Arc::new(crypto));
    let mut transport_config = enable_mtud_if_supported();
    transport_config.max_idle_timeout(Some(VarInt::from_u32(60_000).into()));
    //transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(1)));
    if dtnoption {
        transport_config.max_idle_timeout(Some(VarInt::MAX.into()));
        transport_config.initial_rtt(Duration::new(100000, 0));
        transport_config.receive_window(VarInt::MAX);
        transport_config.datagram_send_buffer_size(usize::MAX);
        transport_config.send_window(u64::MAX);
        transport_config.datagram_receive_buffer_size(Option::Some(usize::MAX));
        transport_config.stream_receive_window(VarInt::MAX);
        transport_config.congestion_controller_factory(
            Arc::new(quinn::congestion::NoCCConfig::default()));
        //let mut ack_frequency_config = quinn::AckFrequencyConfig::default();
        //ack_frequency_config.max_ack_delay(Some(Duration::MAX));
        //transport_config.ack_frequency_config(Some(ack_frequency_config));
        // disable mtu discovery
        let mut mtu_discovery_config = quinn::MtuDiscoveryConfig::default();
        mtu_discovery_config.upper_bound(1200);  //should be INITIAL_MTU
        mtu_discovery_config.interval(Duration::new(1000000,0));
        transport_config.mtu_discovery_config(Some(mtu_discovery_config));
        // connection_id pool
    }
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// Constructs a QUIC endpoint configured for use a client only.
///
/// ## Args
///
/// - server_certs: list of trusted certificates.
#[allow(unused)]
pub fn make_client_endpoint(bind_addr: SocketAddr, dtnoption: bool) -> Result<Endpoint, Box<dyn Error>> {
    let client_cfg = configure_client(dtnoption)?;
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

#[tokio::main]
pub async fn run(options: Opt) -> Result<(), Box<dyn Error>> {
    let url = options.url;
    if url.scheme() != "quic" {
        return Err("URL scheme must be quic".into());
    }

    let remote = (url.host_str().unwrap(), url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or("couldn't resolve to an address")?;

    info!("[client] Connecting to {:?}", remote);

    let endpoint = make_client_endpoint(match options.bind_addr {
        None => if remote.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()
        .unwrap(),
        Some(local) => local,
    }, options.dtn)?;
    // connect to server
    let connection = endpoint
        .connect(remote, url.host_str().unwrap_or("localhost"))
        .unwrap()
        .await
        .unwrap();
    info!("[client] connected: addr={}", connection.remote_address());

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| format!("failed to open stream: {}", e))?;

    let recv_thread = async move {
        let mut buf = vec![0; 2048];
        let mut writer = tokio::io::BufWriter::new(tokio::io::stdout());

        loop {
            match recv.read(&mut buf).await {
                // Return value of `Ok(0)` signifies that the remote has
                // closed
                Ok(None) => {
                    continue;
                }
                Ok(Some(n)) => {
                    debug!("[client] recv data from quic server {} bytes", n);
                    // Copy the data back to socket
                    match writer.write_all(&buf[..n]).await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("[client] write to stdout error: {}", e);
                            return;
                        }
                    }
                }
                Err(err) => {
                    // Unexpected socket error. There isn't much we can do
                    // here so just stop processing.
                    error!("[client] recv data from quic server error: {}", err);
                    return;
                }
            }
            if writer.flush().await.is_err() {
                error!("[client] recv data flush stdout error");
            }
        }
    };

    let write_thread = async move {
        let mut buf = [0; 2048];
        let mut reader = tokio::io::BufReader::new(tokio::io::stdin());

        loop {
            match reader.read(&mut buf).await {
                // Return value of `Ok(0)` signifies that the remote has
                // closed
                Ok(n) => {
                    if n == 0 {
                        continue;
                    }
                    debug!("[client] recv data from stdin {} bytes", n);
                    // Copy the data back to socket
                    if send.write_all(&buf[..n]).await.is_err() {
                        // Unexpected socket error. There isn't much we can
                        // do here so just stop processing.
                        info!("[client] send data to quic server error");
                        return;
                    }
                }
                Err(err) => {
                    // Unexpected socket error. There isn't much we can do
                    // here so just stop processing.
                    info!("[client] recv data from stdin error: {}", err);
                    return;
                }
            }
        }
    };

    let signal_thread = create_signal_thread();

    tokio::select! {
        _ = recv_thread => (),
        _ = write_thread => (),
        _ = signal_thread => connection.close(0u32.into(), b"signal HUP"),
    }

    info!("[client] exit client");

    Ok(())
}

#[cfg(windows)]
fn create_signal_thread() -> impl core::future::Future<Output = ()> {
    async move {
        let mut stream = match ctrl_c() {
            Ok(s) => s,
            Err(e) => {
                error!("[client] create signal stream error: {}", e);
                return;
            }
        };

        stream.recv().await;
        info!("[client] got signal Ctrl-C");
    }
}
#[cfg(not(windows))]
fn create_signal_thread() -> impl core::future::Future<Output = ()> {
    async move {
        let mut stream = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                error!("[client] create signal stream error: {}", e);
                return;
            }
        };

        stream.recv().await;
        info!("[client] got signal HUP");
    }
}
