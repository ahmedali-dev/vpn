use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, SubjectAlternativeName},
    },
};
use russh::{
    Channel,
    keys::{Algorithm, HashAlg, PrivateKey},
    server,
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_openssl::SslStream;

pub struct TestServer {
    pub port: u16,
    pub certificate_pin: String,
    pub ssh_fingerprint: String,
    pub ca: tempfile::NamedTempFile,
    task: JoinHandle<()>,
}
impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn certificate() -> (PKey<Private>, X509) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let serial = openssl::bn::BigNum::from_u32(1)
        .unwrap()
        .to_asn1_integer()
        .unwrap();
    cert.set_serial_number(&serial).unwrap();
    cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    let ext = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&cert.x509v3_context(None, None))
        .unwrap();
    cert.append_extension(ext).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    (key, cert.build())
}
#[derive(Clone)]
struct Echo;
impl server::Handler for Echo {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(if user == "alice" && password == "secret" {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        _: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let mut b = [0; 4096];
            loop {
                match stream.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stream.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = stream.shutdown().await;
        });
        Ok(true)
    }
}
pub async fn server() -> TestServer {
    use std::io::Write;
    let (key, cert) = certificate();
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(&cert.to_pem().unwrap()).unwrap();
    ca.flush().unwrap();
    let pin = hex::encode(Sha256::digest(cert.to_der().unwrap()));
    let ssh = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap();
    let fingerprint = ssh.public_key().fingerprint(HashAlg::Sha256).to_string();
    let config = Arc::new(server::Config {
        keys: vec![ssh],
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    let acceptor = acceptor.build();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut jobs = JoinSet::new();
        loop {
            tokio::select! {v=listener.accept()=>{if let Ok((stream,_))=v{let ssl=openssl::ssl::Ssl::new(acceptor.context()).unwrap();let config=config.clone();jobs.spawn(async move{let mut tls=SslStream::new(ssl,stream).unwrap();if std::pin::Pin::new(&mut tls).accept().await.is_ok()&& let Ok(s)=server::run_stream(config,tls,Echo).await{let _=s.await;}});}},_=jobs.join_next(),if !jobs.is_empty()=>()}
        }
    });
    TestServer {
        port,
        certificate_pin: pin,
        ssh_fingerprint: fingerprint,
        ca,
        task,
    }
}
