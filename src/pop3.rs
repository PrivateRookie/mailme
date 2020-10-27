use std::sync::Arc;

use nom::{
    bytes::complete::tag,
    bytes::complete::take_while,
    multi::many0,
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
// NOTE!!! "~" is not in RFC uidl uid chars, but it does appear in qq email
const UIDL_CHARS: &str = "~!\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";

#[derive(Error, Debug)]
pub enum Pop3Error {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("read/write failed: {0}")]
    IOFailed(String),

    #[error("invalid utf8")]
    InvalidUtf8,

    /// represent -ERR response
    #[error("{0}")]
    ServerErr(String),

    /// response doesn't starts with +OK or -ERR, or end correctly
    #[error("invalid response {0}")]
    UnknownResponse(String),

    #[error("parse error {0}")]
    ParseError(String),
}

pub enum POP3StreamType {
    Basic(TcpStream),
    Tls(TlsStream<TcpStream>),
}

pub struct POP3Client {
    stream: POP3StreamType,
    pub host: String,
    pub port: u16,
    pub is_auth: bool,
}

impl POP3Client {
    pub async fn new_basic(host: &str, port: u16) -> Result<Self, Pop3Error> {
        match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(stream) => Ok(Self {
                host: host.to_string(),
                port,
                stream: POP3StreamType::Basic(stream),
                is_auth: false,
            }),
            Err(e) => Err(Pop3Error::ConnectionFailed(format!("{}", e))),
        }
    }

    pub async fn new_tls(host: &str, port: u16) -> Result<Self, Pop3Error> {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let connector = TlsConnector::from(Arc::new(config));
        match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(tcp_stream) => {
                let domain = DNSNameRef::try_from_ascii_str(host)
                    .map_err(|_| Pop3Error::ConnectionFailed("DNS resolve failed".to_string()))?;
                let stream = connector
                    .connect(domain, tcp_stream)
                    .await
                    .map_err(|e| Pop3Error::ConnectionFailed(format!("{}", e)))?;
                Ok(Self {
                    stream: POP3StreamType::Tls(stream),
                    host: host.to_string(),
                    port,
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
                .map_err(|e| Pop3Error::IOFailed(e.to_string())),
            POP3StreamType::Tls(stream) => stream
                .read(&mut buf)
                .await
                .map_err(|e| Pop3Error::IOFailed(e.to_string())),
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
        if buf[n - 1] == 10 && buf[n - 2] == 13 {
            let resp = String::from_utf8(buf[0..n].to_vec()).map_err(|_| Pop3Error::InvalidUtf8)?;
            log::debug!("[Server] {}", resp);
            remove_response_prefix(&resp)
        } else {
            Err(Pop3Error::UnknownResponse(
                "incomplete response".to_string(),
            ))
        }
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

    pub async fn read_welcome(&mut self) -> Result<String, Pop3Error> {
        self.read_one_line().await
    }

    pub async fn user(&mut self, name: &str) -> Result<(), Pop3Error> {
        self.send_cmd(&format!("USER {}", name)).await?;
        let resp = self.read_one_line().await?;
        assert!(resp.is_empty());
        Ok(())
    }

    pub async fn pass(&mut self, passwd: &str) -> Result<(), Pop3Error> {
        self.send_cmd(&format!("PASS {}", passwd)).await?;
        let resp = self.read_one_line().await?;
        assert!(resp.is_empty());
        self.is_auth = true;
        Ok(())
    }

    pub async fn stat(&mut self) -> Result<POP3Status, Pop3Error> {
        self.send_cmd("STAT").await?;
        let resp = self.read_one_line().await?;
        let (_, (msg_count, _, mailbox_size)) = tuple((take_num, tag(" "), take_num))(&resp)
            .map_err(|_| {
                Pop3Error::ParseError(format!("failed to parse STAT response: {}", resp))
            })?;
        Ok(POP3Status {
            msg_count,
            mailbox_size,
        })
    }

    pub async fn list(&mut self, msg_id: Option<usize>) -> Result<Vec<POP3EmailMeta>, Pop3Error> {
        let cmd = match msg_id {
            Some(msg_id) => format!("LIST {}", msg_id),
            None => format!("LIST"),
        };
        self.send_cmd(&cmd).await?;
        let resp = self.read_one_line().await?;
        if msg_id.is_some() {
            parse_single_meta(&resp).map(|meta| vec![meta])
        } else {
            parse_multi_meta(&resp)
        }
    }

    // TODO should return parsed email struct
    pub async fn retr(&mut self, msg_id: usize) -> Result<String, Pop3Error> {
        self.send_cmd(&format!("RETR {}", msg_id)).await?;
        self.read_multi_line().await
    }

    pub async fn dele(&mut self, msg_id: usize) -> Result<String, Pop3Error> {
        self.send_cmd(&format!("DELE {}", msg_id)).await?;
        self.read_one_line().await
    }

    pub async fn noop(&mut self) -> Result<String, Pop3Error> {
        self.send_cmd("NOOP").await?;
        self.read_one_line().await
    }

    pub async fn rset(&mut self) -> Result<String, Pop3Error> {
        self.send_cmd("RSET").await?;
        self.read_one_line().await
    }

    pub async fn quit(&mut self) -> Result<String, Pop3Error> {
        self.send_cmd("QUIT").await?;
        self.read_one_line().await
    }

    // optional commands:

    // display first <num> lines of email <msg_id>
    pub async fn top(&mut self, msg_id: usize, num: usize) -> Result<String, Pop3Error> {
        self.send_cmd(&format!("TOP {} {}", msg_id, num)).await?;
        self.read_multi_line().await
    }

    pub async fn uidl(&mut self) -> Result<Vec<POP3UidlData>, Pop3Error> {
        self.send_cmd("UIDL").await?;
        let resp = self.read_multi_line().await?;
        let (i, data) = many0(terminated(parse_uidl, tag("\r\n")))(&resp)
            .map_err(|e| Pop3Error::ParseError(e.to_string()))?;
        if i != "." {
            Err(Pop3Error::ParseError(format!("found unparsed data {}", i)))
        } else {
            Ok(data)
        }
    }

    pub async fn uidl_one(&mut self, msg_id: usize) -> Result<POP3UidlData, Pop3Error> {
        self.send_cmd(&format!("UIDL {}", msg_id)).await?;
        let resp = self.read_one_line().await?;
        let (i, uidl_data) = parse_uidl(&resp).map_err(|e| Pop3Error::ParseError(e.to_string()))?;
        if i.len() != 0 {
            Err(Pop3Error::ParseError(format!("found unparsed data {}", i)))
        } else {
            Ok(uidl_data)
        }
    }

    // TODO should return Vec of cap
    pub async fn capa(&mut self) -> Result<String, Pop3Error> {
        self.send_cmd("CAPA").await?;
        self.read_one_line().await
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
        Err(Pop3Error::ServerErr(
            resp.strip_prefix("-ERR")
                .map(|s| s.trim())
                .unwrap()
                .to_string(),
        ))
    } else {
        Err(Pop3Error::UnknownResponse(format!(
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

fn parse_meta(input: &str) -> IResult<&str, POP3EmailMeta> {
    let (i, (message_id, _, message_size)) = tuple((take_num, tag(" "), take_num))(input)?;
    Ok((
        i,
        POP3EmailMeta {
            message_id,
            message_size,
        },
    ))
}

fn parse_single_meta(input: &str) -> Result<POP3EmailMeta, Pop3Error> {
    let (_, meta) = parse_meta(input).map_err(|e| {
        Pop3Error::ParseError(format!("failed to parse single LIST response: {}", e))
    })?;
    Ok(meta)
}

fn parse_multi_meta(input: &str) -> Result<Vec<POP3EmailMeta>, Pop3Error> {
    let parse_many = many1(terminated(parse_meta, tag("\r\n")));
    let (_, ret) = terminated(parse_many, tag("."))(input).map_err(|e| {
        Pop3Error::ParseError(format!("failed to parse multi LIST response: {}", e))
    })?;
    Ok(ret)
}

fn parse_uidl(input: &str) -> IResult<&str, POP3UidlData> {
    let (i, (message_id, _, message_uid)) =
        tuple((take_num, tag(" "), take_while(|c| UIDL_CHARS.contains(c))))(input)?;
    Ok((
        i,
        POP3UidlData {
            message_id,
            message_uid: message_uid.to_string(),
        },
    ))
}

#[derive(Debug, Clone)]
pub struct POP3EmailMeta {
    pub message_id: usize,
    pub message_size: usize,
}

#[derive(Debug, Clone)]
pub struct POP3Status {
    msg_count: usize,
    mailbox_size: usize,
}

#[derive(Debug, Clone)]
pub struct POP3UidlData {
    pub message_id: usize,
    pub message_uid: String,
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
            let mut client = POP3Client::new_tls("pop.qq.com", 995).await.unwrap();
            // let mut stream = POP3Stream::connect("pop.163.com", 110).await.unwrap();
            println!("{:?}", client.read_welcome().await);
            println!("{:?}", client.user(&var("MAILME_USER").unwrap()).await);
            println!("{:?}", client.pass(&var("MAILME_PASSWD").unwrap()).await);
            // println!("{:?}", client.top(1, 10).await);
            // println!("{:?}", client.stat().await);
            // println!("{:?}", client.list(Some(99)).await);
            // println!("{:?}", client.noop().await);
            // println!("{:?}", client.rset().await);
            // println!("{:?}", client.list(None).await);
            println!("{:?}", client.uidl_one(1).await);
            println!("{:?}", client.uidl().await);
            println!("{:?}", client.quit().await);
            // println!("{:?}", client.dele(1).await);
            // println!("{:?}", client.retr(2).await);
        })
    }
}
