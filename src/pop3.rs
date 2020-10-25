use std::sync::Arc;

use thiserror::Error;
use tokio::net::TcpStream;
use tokio::prelude::*;
use tokio_rustls::{client::TlsStream, rustls::ClientConfig, webpki::DNSNameRef, TlsConnector};

// const POP3_PORT: usize = 110;
// const POP3_SSL_PORT: usize = 995;

#[derive(Error, Debug)]
pub enum Pop3Error {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("read line failed: {0}")]
    IOFailed(String),

    #[error("invalid encode")]
    InvalidUtf8,

    #[error("{0}")]
    ResponseError(String),

    #[error("invalid response {0}")]
    InvalidResponse(String),
}

pub enum POP3StreamType {
    Basic(TcpStream),
    Tls(TlsStream<TcpStream>),
}

pub struct POP3Stream {
    stream: POP3StreamType,
    pub is_auth: bool,
}

impl POP3Stream {
    pub async fn connect(host: &str, port: u16) -> Result<Self, Pop3Error> {
        match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(stream) => Ok(Self {
                stream: POP3StreamType::Basic(stream),
                is_auth: false,
            }),
            Err(e) => Err(Pop3Error::ConnectionFailed(format!("{}", e))),
        }
    }

    pub async fn tls_connect(host: &str, port: u16) -> Result<Self, Pop3Error> {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let connector = TlsConnector::from(Arc::new(config));
        match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(tcp_stream) => {
                let domain = DNSNameRef::try_from_ascii_str(host)
                    .map_err(|_| Pop3Error::ConnectionFailed(format!("DNS resolve failed")))?;
                let stream = connector
                    .connect(domain, tcp_stream)
                    .await
                    .map_err(|e| Pop3Error::ConnectionFailed(format!("{}", e)))?;
                Ok(Self {
                    stream: POP3StreamType::Tls(stream),
                    is_auth: false,
                })
            }
            Err(e) => Err(Pop3Error::ConnectionFailed(format!("{}", e))),
        }
    }

    async fn read_line(&mut self) -> Result<String, Pop3Error> {
        let mut buf = [0; 1024];
        match &mut self.stream {
            POP3StreamType::Basic(stream) => stream
                .read(&mut buf)
                .await
                .map_err(|e| Pop3Error::IOFailed(format!("{}", e)))?,
            POP3StreamType::Tls(stream) => stream
                .read(&mut buf)
                .await
                .map_err(|e| Pop3Error::IOFailed(format!("{}", e)))?,
        };

        let end = buf.iter().position(|&i| i == 0);
        if end.is_none() {
            return Err(Pop3Error::InvalidResponse(format!(
                "incomplete response {:?}",
                buf
            )));
        }
        let resp =
            String::from_utf8(buf[0..end.unwrap()].to_vec()).map_err(|_| Pop3Error::InvalidUtf8)?;
        log::debug!("[Server] {}", resp);
        if resp.starts_with("+OK") {
            Ok(resp
                .strip_prefix("+OK")
                .map(|s| s.trim())
                .unwrap()
                .to_string())
        } else if resp.starts_with("-ERR") {
            Err(Pop3Error::ResponseError(format!(
                "{}",
                resp.strip_prefix("-ERR").map(|s| s.trim()).unwrap()
            )))
        } else {
            Err(Pop3Error::InvalidResponse(format!(
                "unknown response {}",
                resp
            )))
        }
    }

    async fn send_cmd(&mut self, cmd: &str) -> Result<String, Pop3Error> {
        let cmd = format!("{}\r\n", cmd);
        log::debug!("[Client] {}", cmd);
        match &mut self.stream {
            POP3StreamType::Basic(stream) => stream
                .write(cmd.as_bytes())
                .await
                .map_err(|e| Pop3Error::IOFailed(format!("{}", e)))?,
            POP3StreamType::Tls(stream) => stream
                .write(cmd.as_bytes())
                .await
                .map_err(|e| Pop3Error::IOFailed(format!("{}", e)))?,
        };
        self.read_line().await
    }

    pub async fn read_welcome(&mut self) -> Result<Pop3Response, Pop3Error> {
        let resp = self.read_line().await?;
        Ok(Pop3Response::Welcome(resp))
    }

    pub async fn capa(&mut self) -> Result<String, Pop3Error> {
        self.send_cmd("CAPA").await
    }

    pub async fn user(&mut self, name: &str) -> Result<Pop3Response, Pop3Error> {
        self.send_cmd(&format!("USER {}", name)).await?;
        Ok(Pop3Response::Empty)
    }

    pub async fn pass(&mut self, passwd: &str) -> Result<Pop3Response, Pop3Error> {
        self.send_cmd(&format!("PASS {}", passwd)).await?;
        Ok(Pop3Response::Empty)
    }

    pub async fn stat(&mut self) -> Result<Pop3Response, Pop3Error> {
        let resp = self.send_cmd("STAT").await?;
        println!("{}", resp);
        Ok(Pop3Response::Empty)
    }

    pub async fn list(&mut self, which: Option<&str>) -> Result<String, Pop3Error> {
        self.send_cmd(&format!("LIST {}", which.unwrap_or("")))
            .await
    }
}

#[derive(Debug, Clone)]
pub enum Pop3Response {
    Welcome(String),
    Empty,
    Status {
        msg_count: usize,
        mailbox_size: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::var;
    use tokio::runtime::Runtime;

    #[test]
    fn test_connect() {
        dotenv::dotenv().ok();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut stream = POP3Stream::tls_connect("pop.qq.com", 995).await.unwrap();
            // let mut stream = POP3Stream::connect("pop.163.com", 110).await.unwrap();
            println!("{:?}", stream.read_welcome().await);
            println!("{:?}", stream.user(&var("USERNAME").unwrap()).await);
            println!("{:?}", stream.pass(&var("PASSWD").unwrap()).await);
            stream.stat().await.unwrap();
            println!("{:?}", stream.list(None).await);
        })
    }
}
