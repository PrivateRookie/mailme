use std::sync::Arc;

use nom::{
    bytes::complete::tag,
    multi::many1,
    sequence::{terminated, tuple},
    IResult,
};
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

    #[error("parse error {0}")]
    ParseError(String),
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

    async fn try_read(&mut self, mut buf: &mut [u8]) -> Result<usize, Pop3Error> {
        match &mut self.stream {
            POP3StreamType::Basic(stream) => stream
                .read(&mut buf)
                .await
                .map_err(|e| Pop3Error::IOFailed(format!("{}", e))),
            POP3StreamType::Tls(stream) => stream
                .read(&mut buf)
                .await
                .map_err(|e| Pop3Error::IOFailed(format!("{}", e))),
        }
    }

    async fn read_multi_line(&mut self) -> Result<String, Pop3Error> {
        let mut ret = vec![];
        let mut buf = [0; 1024];
        loop {
            let n = self.try_read(&mut buf).await?;
            buf[0..n].iter().for_each(|&v| ret.push(v));
            // check if meed end of response "\r\n.\r\n"
            if buf[n - 1] == 10
                && buf[n - 2] == 13
                && buf[n - 3] == 46
                && buf[n - 4] == 10
                && buf[n - 5] == 13
            {
                break;
            }
        }
        let resp = String::from_utf8(ret).map_err(|_| Pop3Error::InvalidUtf8)?;
        remove_response_prefix(&resp)
    }

    async fn read_one_line(&mut self) -> Result<String, Pop3Error> {
        let mut buf = [0; 1024];
        let n = self.try_read(&mut buf).await?;
        let resp = String::from_utf8(buf[0..n].to_vec()).map_err(|_| Pop3Error::InvalidUtf8)?;
        log::debug!("[Server] {}", resp);
        remove_response_prefix(&resp)
    }

    async fn send_cmd(&mut self, cmd: &str) -> Result<usize, Pop3Error> {
        let cmd = format!("{}\r\n", cmd);
        log::debug!("[Client] {}", cmd);
        match &mut self.stream {
            POP3StreamType::Basic(stream) => stream
                .write(cmd.as_bytes())
                .await
                .map_err(|e| Pop3Error::IOFailed(format!("{}", e))),
            POP3StreamType::Tls(stream) => stream
                .write(cmd.as_bytes())
                .await
                .map_err(|e| Pop3Error::IOFailed(format!("{}", e))),
        }
    }

    pub async fn read_welcome(&mut self) -> Result<Pop3Response, Pop3Error> {
        let resp = self.read_one_line().await?;
        Ok(Pop3Response::Welcome(resp))
    }

    pub async fn capa(&mut self) -> Result<String, Pop3Error> {
        self.send_cmd("CAPA").await?;
        self.read_one_line().await
    }

    pub async fn user(&mut self, name: &str) -> Result<Pop3Response, Pop3Error> {
        self.send_cmd(&format!("USER {}", name)).await?;
        self.read_one_line().await?;
        Ok(Pop3Response::Empty)
    }

    pub async fn pass(&mut self, passwd: &str) -> Result<Pop3Response, Pop3Error> {
        self.send_cmd(&format!("PASS {}", passwd)).await?;
        self.read_one_line().await?;
        Ok(Pop3Response::Empty)
    }

    pub async fn stat(&mut self) -> Result<Pop3Response, Pop3Error> {
        self.send_cmd("STAT").await?;
        let resp = self.read_one_line().await?;
        let (_, (msg_count, _, mailbox_size)) = tuple((take_num, tag(" "), take_num))(&resp)
            .map_err(|_| {
                Pop3Error::ParseError(format!("failed to parse STAT response: {}", resp))
            })?;
        Ok(Pop3Response::Status {
            msg_count,
            mailbox_size,
        })
    }

    pub async fn list(&mut self, msg_id: Option<usize>) -> Result<Pop3Response, Pop3Error> {
        let cmd = match msg_id {
            Some(msg_id) => format!("LIST {}", msg_id),
            None => format!("LIST"),
        };
        self.send_cmd(&cmd).await?;
        let resp = self.read_one_line().await?;
        if msg_id.is_some() {
            parse_single_meta(&resp).map(|meta| Pop3Response::List(vec![meta]))
        } else {
            parse_multi_meta(&resp).map(|meta| Pop3Response::List(meta))
        }
    }

    pub async fn retr(&mut self, msg_id: usize) -> Result<String, Pop3Error> {
        self.send_cmd(&format!("RETR {}", msg_id)).await?;
        self.read_multi_line().await
    }
}

fn remove_response_prefix(resp: &str) -> Result<String, Pop3Error> {
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

fn take_num(input: &str) -> IResult<&str, usize> {
    let (i, num) = nom::character::complete::digit1(input)?;
    let num = num.parse::<usize>().unwrap();
    Ok((i, num))
}

fn parse_meta(input: &str) -> IResult<&str, Pop3EmailMeta> {
    let (i, (message_id, _, message_size)) = tuple((take_num, tag(" "), take_num))(input)?;
    Ok((
        i,
        Pop3EmailMeta {
            message_id,
            message_size,
        },
    ))
}

fn parse_single_meta(input: &str) -> Result<Pop3EmailMeta, Pop3Error> {
    let (_, meta) = parse_meta(input).map_err(|e| {
        Pop3Error::ParseError(format!("failed to parse single LIST response: {}", e))
    })?;
    Ok(meta)
}

fn parse_multi_meta(input: &str) -> Result<Vec<Pop3EmailMeta>, Pop3Error> {
    let parse_many = many1(terminated(parse_meta, tag("\r\n")));
    let (_, ret) = terminated(parse_many, tag("."))(input).map_err(|e| {
        Pop3Error::ParseError(format!("failed to parse multi LIST response: {}", e))
    })?;
    Ok(ret)
}

#[derive(Debug, Clone)]
pub struct Pop3EmailMeta {
    pub message_id: usize,
    pub message_size: usize,
}

#[derive(Debug, Clone)]
pub enum Pop3Response {
    Welcome(String),
    Empty,
    Status {
        msg_count: usize,
        mailbox_size: usize,
    },
    List(Vec<Pop3EmailMeta>),
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
            println!("{:?}", stream.stat().await);
            println!("{:?}", stream.list(Some(99)).await);
            println!("{:?}", stream.list(None).await);
            println!("{:?}", stream.retr(2).await);
        })
    }
}
