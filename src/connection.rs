//! Route-aware connection builders and single-exchange HTTP clients.
use crate::{
    net::{self, BoxedIo, ConnectionOptions},
    route::{Endpoint, Route},
};
use anyhow::{Context, Result};
use std::{
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    DirectTcp,
    DirectTls,
    ForwardProxy,
    ConnectTunnel,
}

pub struct Connection {
    stream: BoxedIo,
    route: Route,
    transport: Transport,
    options: ConnectionOptions,
}
impl Connection {
    pub async fn direct(
        destination: &Endpoint,
        options: &ConnectionOptions,
        timeout: Duration,
    ) -> Result<Self> {
        Self::connect(Route::Direct, destination, false, options, timeout).await
    }
    pub async fn direct_tls(
        destination: &Endpoint,
        options: &ConnectionOptions,
        timeout: Duration,
    ) -> Result<Self> {
        Ok(Self {
            stream: net::connect_direct_tls(destination, options, timeout).await?,
            route: Route::Direct,
            transport: Transport::DirectTls,
            options: options.clone(),
        })
    }
    pub async fn proxy(
        endpoint: Endpoint,
        tls: bool,
        options: &ConnectionOptions,
        timeout: Duration,
    ) -> Result<Self> {
        let route = if tls {
            Route::Https(endpoint.clone())
        } else {
            Route::Http(endpoint.clone())
        };
        Self::connect(route, &endpoint, false, options, timeout).await
    }
    pub async fn tunnel(
        route: Route,
        destination: &Endpoint,
        options: &ConnectionOptions,
        timeout: Duration,
    ) -> Result<Self> {
        Self::connect(route, destination, true, options, timeout).await
    }
    pub async fn connect(
        route: Route,
        destination: &Endpoint,
        tunnel: bool,
        options: &ConnectionOptions,
        timeout: Duration,
    ) -> Result<Self> {
        let transport = match route {
            Route::Direct => Transport::DirectTcp,
            _ if tunnel => Transport::ConnectTunnel,
            _ => Transport::ForwardProxy,
        };
        Ok(Self {
            stream: net::connect(&route, destination, tunnel, options, timeout).await?,
            route,
            transport,
            options: options.clone(),
        })
    }
    pub fn route(&self) -> &Route {
        &self.route
    }
    pub fn transport(&self) -> Transport {
        self.transport
    }
    pub fn into_stream(self) -> BoxedIo {
        self.stream
    }
    /// Send one streaming HTTP request. Callers choose origin/absolute form;
    /// only a forward-proxy transport generates a proxy authorization header.
    pub async fn send<B>(
        self,
        mut request: http::Request<B>,
    ) -> Result<http::Response<hyper::body::Incoming>>
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        request
            .headers_mut()
            .remove(http::header::PROXY_AUTHORIZATION);
        if self.transport == Transport::ForwardProxy
            && let Route::Http(endpoint) | Route::Https(endpoint) = &self.route
            && let Some(authorization) = self.options.auth.authorization(&endpoint.host).await?
        {
            request
                .headers_mut()
                .insert(http::header::PROXY_AUTHORIZATION, authorization);
        }
        request.headers_mut().insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );
        let (mut sender, driver) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(self.stream))
                .await
                .context("HTTP connection handshake")?;
        tokio::spawn(async move {
            if let Err(error) = driver.await {
                tracing::debug!(%error, "HTTP connection ended");
            }
        });
        sender
            .send_request(request)
            .await
            .context("HTTP request exchange")
    }
}
impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}
