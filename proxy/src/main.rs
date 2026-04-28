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
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;

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

    let addr: SocketAddr = listen_addr.parse().expect("invalid listen address");
    let listener = TcpListener::bind(addr).await.expect("bind failed");
    eprintln!("notme-proxy: listening on {addr}");

    loop {
        let (stream, _peer) = listener.accept().await.expect("accept failed");
        let tls_config = tls_config.clone();

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
}
