//! A minimal SOCKS5 client (RFC 1928, no authentication, CONNECT by domain name), enough to reach
//! Tor v3 and I2P destinations through a local tor or i2pd.

use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn err(msg: &str) -> io::Error {
    io::Error::other(msg.to_string())
}

/// Open a connection to `host:port` through the SOCKS5 proxy at `proxy`. The caller bounds the
/// whole call with a timeout.
pub async fn connect(proxy: SocketAddr, host: &str, port: u16) -> io::Result<TcpStream> {
    if host.is_empty() || host.len() > 255 {
        return Err(err("socks: bad host length"));
    }
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[5, 1, 0]).await?; // version 5, one method, "no authentication"
    let mut choice = [0u8; 2];
    s.read_exact(&mut choice).await?;
    if choice != [5, 0] {
        return Err(err("socks: proxy refused no-auth"));
    }
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[5, 1, 0, 3, host.len() as u8]);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(err("socks: bad reply version"));
    }
    if head[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("socks: connect failed, code {}", head[1]),
        ));
    }
    // Skip the bound address the proxy reports; its length depends on the type.
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        _ => return Err(err("socks: bad address type in reply")),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await?;
    Ok(s)
}
