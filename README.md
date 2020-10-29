# mailme

Async POP3 client impl with Rust.

## supported methods

**some pop3 server may not some methods list below**

- user
- pass
- stat
- list (split into list_one and list)
- retr
- dele
- noop
- rset
- quit
- top
- uidl (split into uidl_one and uidl)
- capa
- apop


## example

add tokio and mailme to dep

```toml
tokio = { version = "0.3.1", features = ["io-util", "io-std", "net", "rt", "rt-multi-thread"] }
mailme = "0.1.1"
```

```rust
use pop3::POP3Client;
use tokio::runtime::Runtime;

fn main() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // if not tls connection, use new_basic instead
        let mut client = POP3Client::new_tls("pop.qq.com", 995).await.unwrap();
        // remember to read welcome message
        println!("{:?}", client.read_welcome().await);
        // login
        println!("{:?}", client.user("PrivateRookie").await);
        println!("{:?}", client.pass("踏遍青山人未老").await);

        // do some thing
        println!("{:?}", client.stat().await);
    })
}
```


## Todos

- [x] impl POP3 protocol(:heavy_check_mark:)
- [ ] pop3 retr return parsed email
- [ ] support custom ssl context
- [ ] calling `quit` when pop3 client drop ?
- [ ] impl imap protocol
- [ ] add monitor methods


## Refs

- [POP3 RFC](https://tools.ietf.org/html/rfc1939)
- [Python POP3 IMPL](https://github.com/python/cpython/blob/3.9/Lib/poplib.py)
- [Rust POP3 IMPL](https://github.com/mattnenterprise/rust-pop3/blob/master/src/pop3.rs)
