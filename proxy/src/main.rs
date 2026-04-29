//! notme-proxy — mTLS forward proxy for workerd.
//!
//! Receives HTTP proxy-style requests from workerd (plain HTTP on UDS/localhost),
//! connects to the target with HTTPS + bridge cert (mTLS), returns the response.
//!
//! The bridge cert private key lives only in this process's memory.
//! workerd Workers never touch the key — they just call fetch() normally.
//!
//! Usage:
//!   notme-proxy --cert bridge.pem --key bridge-key.pem --listen 127.0.0.1:1080
//!   notme-proxy --cert bridge.pem --key bridge-key.pem --listen unix:/run/notme/mtls.sock

use std::env;
use std::fs;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, UnixListener};

#[derive(Debug, PartialEq, Eq)]
enum ListenAddr {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

fn parse_listen_addr(s: &str) -> Result<ListenAddr, String> {
    if let Some(path) = s.strip_prefix("unix:") {
        if path.is_empty() {
            return Err("unix: prefix requires a socket path".to_string());
        }
        Ok(ListenAddr::Unix(PathBuf::from(path)))
    } else {
        s.parse::<SocketAddr>()
            .map(ListenAddr::Tcp)
            .map_err(|e| format!("invalid listen address {s:?}: {e}"))
    }
}

/// Remove a stale socket file at `path`. Refuses to remove non-socket files so
/// an operator typo (e.g. `unix:./bridge-cert.pem`) can't clobber unrelated
/// data. Uses `symlink_metadata` so a symlink at the path is treated as
/// "not a socket" rather than being followed.
fn try_remove_socket_file(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path)
            .map_err(|e| format!("remove stale socket {}: {e}", path.display())),
        Ok(_) => Err(format!(
            "refusing to remove non-socket at {}",
            path.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("stat {}: {e}", path.display())),
    }
}

/// Bind a UDS listener with owner-only (0600) permissions on the socket file.
/// The bridge cert means anyone who can `connect()` to this socket can fetch
/// as the bridge identity, so we tighten perms immediately after bind.
fn bind_unix_listener(path: &std::path::Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::PermissionsExt;
    try_remove_socket_file(path)?;
    let listener = UnixListener::bind(path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(listener)
}

/// Load cert chain + private key from PEM files.
fn load_certs_and_key(
    cert_path: &str,
    key_path: &str,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert_file = fs::File::open(cert_path).expect("open cert file");
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .expect("parse cert PEM");

    let key_file = fs::File::open(key_path).expect("open key file");
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .expect("parse key PEM")
        .expect("no private key found in PEM");

    (certs, key)
}

/// Build a rustls ClientConfig with the bridge cert for mTLS.
fn build_mtls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("invalid client cert/key");

    Arc::new(config)
}

/// Handle a proxy-style HTTP request:
///   GET https://target.example.com/path HTTP/1.1
/// Connect to target with mTLS, forward request, return response.
async fn handle_proxy(
    tls_config: Arc<rustls::ClientConfig>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let uri = req.uri().clone();
    let method = req.method().clone();
    let headers = req.headers().clone();

    // Parse target from proxy-style URI
    let host = uri.host().ok_or("no host in request URI")?;
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
    let use_tls = uri.scheme_str() == Some("https");
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Collect body (consumes req)
    let body_bytes = req.collect().await?.to_bytes();

    // Build forward request (path-style, not proxy-style)
    let mut forward_req = Request::builder()
        .method(&method)
        .uri(path);

    for (name, value) in &headers {
        if name == "proxy-connection" || name == "proxy-authorization" {
            continue;
        }
        forward_req = forward_req.header(name, value);
    }
    forward_req = forward_req.header("host", host);

    let forward_req = forward_req.body(Full::new(body_bytes))?;

    if use_tls {
        // mTLS connection — the bridge cert is presented during the TLS handshake
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config((*tls_config).clone())
            .https_only()
            .enable_http1()
            .build();

        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);

        // Reconstruct full URI for the client
        let full_uri = format!("https://{}:{}{}", host, port, path);
        let mut client_req = Request::builder()
            .method(forward_req.method())
            .uri(full_uri);
        for (name, value) in forward_req.headers() {
            client_req = client_req.header(name, value);
        }
        let client_req = client_req.body(forward_req.into_body())?;

        let resp = client.request(client_req).await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.collect().await?.to_bytes();

        let mut response = Response::builder().status(status);
        for (name, value) in &headers {
            response = response.header(name, value);
        }
        Ok(response.body(Full::new(body))?)
    } else {
        // Plain HTTP — no mTLS needed, just forward
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();

        let full_uri = format!("http://{}:{}{}", host, port, path);
        let mut client_req = Request::builder()
            .method(forward_req.method())
            .uri(full_uri);
        for (name, value) in forward_req.headers() {
            client_req = client_req.header(name, value);
        }
        let client_req = client_req.body(forward_req.into_body())?;

        let resp = client.request(client_req).await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.collect().await?.to_bytes();

        let mut response = Response::builder().status(status);
        for (name, value) in &headers {
            response = response.header(name, value);
        }
        Ok(response.body(Full::new(body))?)
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let cert_path = args
        .iter()
        .position(|a| a == "--cert")
        .map(|i| args[i + 1].as_str())
        .unwrap_or("bridge-cert.pem");

    let key_path = args
        .iter()
        .position(|a| a == "--key")
        .map(|i| args[i + 1].as_str())
        .unwrap_or("bridge-key.pem");

    let listen_addr = args
        .iter()
        .position(|a| a == "--listen")
        .map(|i| args[i + 1].as_str())
        .unwrap_or("127.0.0.1:1080");

    eprintln!("notme-proxy: loading cert from {cert_path}, key from {key_path}");
    let (certs, key) = load_certs_and_key(cert_path, key_path);
    let tls_config = build_mtls_config(certs, key);
    eprintln!("notme-proxy: mTLS config ready");

    let listen = parse_listen_addr(listen_addr).expect("invalid listen address");
    match listen {
        ListenAddr::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await.expect("bind failed");
            eprintln!("notme-proxy: listening on tcp {addr}");
            loop {
                let (stream, _peer) = listener.accept().await.expect("accept failed");
                spawn_conn(stream, tls_config.clone());
            }
        }
        ListenAddr::Unix(path) => {
            let listener = bind_unix_listener(&path).expect("bind unix listener");
            eprintln!("notme-proxy: listening on unix {} (mode 0600)", path.display());
            loop {
                let (stream, _peer) = listener.accept().await.expect("accept failed");
                spawn_conn(stream, tls_config.clone());
            }
        }
    }
}

fn spawn_conn<S>(stream: S, tls_config: Arc<rustls::ClientConfig>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let io = TokioIo::new(stream);
        let service = service_fn(move |req| {
            let tls_config = tls_config.clone();
            handle_proxy(tls_config, req)
        });
        if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
            eprintln!("notme-proxy: connection error: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_test_path(label: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "notme-proxy-test-{}-{}-{}.sock",
            std::process::id(),
            label,
            n
        ))
    }

    #[test]
    fn parses_tcp_listen_addr() {
        let addr = parse_listen_addr("127.0.0.1:1080").expect("parses");
        assert_eq!(addr, ListenAddr::Tcp("127.0.0.1:1080".parse().unwrap()));
    }

    #[test]
    fn parses_unix_listen_addr() {
        let addr = parse_listen_addr("unix:/run/notme/mtls.sock").expect("parses");
        assert_eq!(addr, ListenAddr::Unix(PathBuf::from("/run/notme/mtls.sock")));
    }

    #[test]
    fn parses_unix_relative_path() {
        let addr = parse_listen_addr("unix:./mtls.sock").expect("parses");
        assert_eq!(addr, ListenAddr::Unix(PathBuf::from("./mtls.sock")));
    }

    #[test]
    fn rejects_empty_unix_path() {
        let err = parse_listen_addr("unix:").expect_err("should reject");
        assert!(err.contains("requires a socket path"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_tcp_addr() {
        assert!(parse_listen_addr("not-a-real-addr").is_err());
    }

    #[test]
    fn try_remove_socket_file_is_noop_when_absent() {
        let path = unique_test_path("absent");
        try_remove_socket_file(&path).expect("absent path is ok");
    }

    #[test]
    fn try_remove_socket_file_refuses_regular_file() {
        let path = unique_test_path("regular");
        std::fs::write(&path, b"important-data").unwrap();
        let err = try_remove_socket_file(&path).expect_err("must refuse");
        assert!(err.contains("non-socket"), "got: {err}");
        assert!(path.exists(), "regular file must not be deleted");
        assert_eq!(std::fs::read(&path).unwrap(), b"important-data");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn try_remove_socket_file_refuses_symlink_to_regular_file() {
        let target = unique_test_path("symlink-target");
        let link = unique_test_path("symlink-link");
        std::fs::write(&target, b"do-not-delete").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = try_remove_socket_file(&link).expect_err("must refuse");
        assert!(err.contains("non-socket"), "got: {err}");
        assert!(target.exists(), "symlink target must remain intact");
        assert_eq!(std::fs::read(&target).unwrap(), b"do-not-delete");
        std::fs::remove_file(&link).ok();
        std::fs::remove_file(&target).ok();
    }

    #[tokio::test]
    async fn bind_unix_listener_sets_owner_only_perms() {
        use std::os::unix::fs::PermissionsExt;
        let sock = unique_test_path("perms");
        let _listener = bind_unix_listener(&sock).expect("bind");
        let mode = fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must be owner-only — bridge cert is sensitive");
        fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn bind_unix_listener_replaces_stale_socket() {
        let sock = unique_test_path("stale");
        // Create a real socket file via a transient bind+drop.
        {
            let _ = UnixListener::bind(&sock).expect("first bind");
        }
        assert!(sock.exists(), "stale socket file should remain after drop");
        let _listener = bind_unix_listener(&sock).expect("rebind over stale");
        assert!(sock.exists());
        fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn bind_unix_listener_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let sock = unique_test_path("round-trip");
        let listener = bind_unix_listener(&sock).expect("bind");
        let (client, accepted) = tokio::join!(
            tokio::net::UnixStream::connect(&sock),
            listener.accept(),
        );
        let mut client = client.expect("connect");
        let (mut server, _peer) = accepted.expect("accept");
        client.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 1];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"x");
        fs::remove_file(&sock).ok();
    }
}
