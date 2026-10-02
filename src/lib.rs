//! Reusable PAC, authentication, connection, proxy, DNS and process interfaces.
pub mod auth;
pub mod config;
pub mod dns;
pub mod desktop;
pub mod net;
pub mod pac;
pub mod platform;
pub mod proxy;
pub mod route;
pub mod tools;
pub const VERSION: &str = env!("PRODUCT_VERSION");
pub const DNS_VERSION: &str = "0.6.0";
pub const PLATFORM: &str = env!("PRODUCT_PLATFORM");
pub const ARCH: &str = env!("PRODUCT_ARCH");
