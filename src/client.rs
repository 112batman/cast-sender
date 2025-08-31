use std::net::SocketAddr;
use std::sync::Arc;

use async_net::TcpStream;
use futures_rustls::client::TlsStream;
use futures_rustls::TlsConnector;
use futures_rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use futures_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use futures_rustls::rustls::client::ServerCertVerifierBuilder;
use futures_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use prost::Message;
use smol::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use smol::lock::Mutex;

use super::proto;
use super::{namespace::NamespaceUrn, Error, Payload};

#[derive(Debug, Clone)]
pub struct Response {
    pub source_id: String,
    pub destination_id: String,
    // Probably not strictly necessary, since the namespace can be derived
    // using the payload, but this may not have any guarantee of correctness,
    // since the namespace may differ from the deserialized enum variant.
    pub namespace: NamespaceUrn,
    pub payload: Payload,
    // Part of the payload
    pub request_id: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Client {
    read_stream: Arc<Mutex<ReadHalf<TlsStream<TcpStream>>>>,
    write_stream: Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
}

#[derive(Debug)]
struct AcceptAllCertsCertVerifier {}
impl ServerCertVerifier for AcceptAllCertsCertVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>, ocsp_response: &[u8], now: UnixTime) -> Result<ServerCertVerified, futures_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, futures_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, futures_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ]
    }
}

impl Client {
    pub async fn connect(addr: &str) -> Result<Self, Error> {
        let addr = SocketAddr::new(addr.parse()?, 8009);

        // Casts devices are using self signed certs
        let tls_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAllCertsCertVerifier {}))
            .with_no_client_auth();
        let tls_connector = TlsConnector::from(Arc::new(tls_config));
        let tcp_stream = TcpStream::connect(&addr).await?;

        let tls_stream = tls_connector
            .connect(ServerName::from(addr.ip()), tcp_stream.clone())
            .await?;

        let (read_stream, write_stream) = smol::io::split(tls_stream);

        Ok(Self {
            read_stream: Arc::new(Mutex::new(read_stream)),
            write_stream: Arc::new(Mutex::new(write_stream)),
        })
    }

    pub async fn receive(&self) -> Result<Response, Error> {
        let mut read_stream = self.read_stream.lock().await;

        // The first package is a u32 specifying the packet length....
        let mut buf: [u8; 4] = [0; 4];
        read_stream.read_exact(&mut buf).await?;
        let len = u32::from_be_bytes(buf);

        // ... then get the actual package with the specified length
        let mut buf: Vec<u8> = vec![0; len as usize];
        read_stream.read_exact(&mut buf).await?;

        let msg: proto::CastMessage = proto::CastMessage::decode(&buf[..])?;
        let ns: NamespaceUrn = msg.namespace.parse().unwrap();
        let mut pl: PayloadData = serde_json::from_str(msg.payload_utf8())?;

        if let Payload::Custom(u) = &mut pl.data {
            u.namespace = ns.clone();
        };

        debug!(
            "[RECV] {} -> {} | Namespace: {:?} | Request: {:?}",
            msg.source_id, msg.destination_id, ns, pl.request_id
        );
        debug!("       {:#?}", pl);
        Ok(Response {
            source_id: msg.source_id,
            destination_id: msg.destination_id,
            namespace: ns,
            payload: pl.data,
            request_id: pl.request_id,
        })
    }

    pub async fn send<P: Into<Payload>>(
        &self,
        destination_id: String,
        payload: P,
        request_id: Option<u32>,
    ) -> Result<(), Error> {
        let payload: Payload = payload.into();
        let payload_data = PayloadData {
            request_id,
            data: payload.clone(),
        };

        let payload_json = serde_json::to_string(&payload_data).unwrap();
        let msg = proto::CastMessage {
            protocol_version: proto::cast_message::ProtocolVersion::Castv210.into(),
            source_id: "sender-0".into(),
            destination_id,
            namespace: payload.namespace().to_string(),
            payload_type: proto::cast_message::PayloadType::String.into(),
            payload_utf8: Some(payload_json.clone()),
            payload_binary: None,
            continued: None,
            remaining_length: None,
        };

        debug!(
            "[SEND] {} -> {} | Namespace: {:?} | Request: {:?}",
            msg.source_id,
            msg.destination_id,
            payload.namespace(),
            request_id,
        );
        debug!("       {}", payload_json);

        let mut write_stream = self.write_stream.lock().await;
        let len: u32 = msg.encoded_len().try_into().unwrap();

        // First send package length
        write_stream.write_all(&len.to_be_bytes()).await?;

        // Then the actual package
        write_stream.write_all(&msg.encode_to_vec()).await?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PayloadData {
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<u32>,
    #[serde(flatten)]
    data: Payload,
}
