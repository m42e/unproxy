//! TCP CONNECT handshakes for SOCKS4a and SOCKS5 upstreams.
use anyhow::{Context, Result, bail, ensure};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{net::AsyncIo, route::Endpoint};

pub(crate) async fn handshake(
    stream: &mut impl AsyncIo,
    destination: &Endpoint,
    version5: bool,
    credentials: Option<(String, String)>,
) -> Result<bool> {
    if version5 {
        socks5(stream, destination, credentials).await
    } else {
        socks4(stream, destination).await?;
        Ok(false)
    }
}

async fn socks4(stream: &mut impl AsyncIo, destination: &Endpoint) -> Result<()> {
    let mut request = vec![4, 1];
    request.extend_from_slice(&destination.port.to_be_bytes());
    let hostname = match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.extend_from_slice(&ip.octets());
            false
        }
        Ok(IpAddr::V6(_)) => bail!("SOCKS4 does not support IPv6 destinations"),
        Err(_) => {
            ensure!(
                !destination.host.is_empty()
                    && destination.host.len() <= 255
                    && !destination.host.contains('\0'),
                "invalid SOCKS4a destination hostname"
            );
            request.extend_from_slice(&[0, 0, 0, 1]);
            true
        }
    };
    request.push(0); // Empty USERID; netrc passwords are only used with SOCKS5.
    if hostname {
        request.extend_from_slice(destination.host.as_bytes());
        request.push(0);
    }
    stream.write_all(&request).await.context("SOCKS4 request")?;
    let mut reply = [0; 8];
    stream
        .read_exact(&mut reply)
        .await
        .context("SOCKS4 reply")?;
    ensure!(reply[0] == 0, "invalid SOCKS4 reply version");
    ensure!(
        reply[1] == 90,
        "SOCKS4 CONNECT rejected (status {})",
        reply[1]
    );
    Ok(())
}

async fn socks5(
    stream: &mut impl AsyncIo,
    destination: &Endpoint,
    credentials: Option<(String, String)>,
) -> Result<bool> {
    let greeting: &[u8] = if credentials.is_some() {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    stream
        .write_all(greeting)
        .await
        .context("SOCKS5 greeting")?;
    let mut selection = [0; 2];
    stream
        .read_exact(&mut selection)
        .await
        .context("SOCKS5 method selection")?;
    ensure!(selection[0] == 5, "invalid SOCKS5 method version");
    let authenticated = match selection[1] {
        0 => false,
        2 => {
            let (username, password) = credentials
                .context("SOCKS5 selected unoffered username/password authentication")?;
            ensure!(
                (1..=255).contains(&username.len()) && (1..=255).contains(&password.len()),
                "SOCKS5 username and password must each contain 1–255 bytes"
            );
            let mut auth = vec![1, username.len() as u8];
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream
                .write_all(&auth)
                .await
                .context("SOCKS5 authentication")?;
            let mut reply = [0; 2];
            stream
                .read_exact(&mut reply)
                .await
                .context("SOCKS5 authentication reply")?;
            ensure!(reply == [1, 0], "SOCKS5 authentication rejected");
            true
        }
        method => bail!("SOCKS5 unsupported authentication method {method}"),
    };
    let mut request = vec![5, 1, 0];
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            ensure!(
                !destination.host.is_empty()
                    && destination.host.len() <= 255
                    && !destination.host.contains('\0'),
                "invalid SOCKS5 destination hostname"
            );
            request.extend_from_slice(&[3, destination.host.len() as u8]);
            request.extend_from_slice(destination.host.as_bytes());
        }
    }
    request.extend_from_slice(&destination.port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .context("SOCKS5 CONNECT request")?;
    let mut reply = [0; 4];
    stream
        .read_exact(&mut reply)
        .await
        .context("SOCKS5 CONNECT reply")?;
    ensure!(
        reply[0] == 5 && reply[2] == 0,
        "invalid SOCKS5 CONNECT reply"
    );
    ensure!(
        reply[1] == 0,
        "SOCKS5 CONNECT rejected (status {})",
        reply[1]
    );
    let address_len = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let len = stream
                .read_u8()
                .await
                .context("SOCKS5 bound hostname length")?;
            ensure!(len > 0, "invalid SOCKS5 bound hostname length");
            usize::from(len)
        }
        kind => bail!("invalid SOCKS5 reply address type {kind}"),
    };
    let mut bound = vec![0; address_len + 2];
    stream
        .read_exact(&mut bound)
        .await
        .context("SOCKS5 bound address")?;
    Ok(authenticated)
}
