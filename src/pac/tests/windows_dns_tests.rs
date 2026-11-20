use super::super::classify_windows_dns_lookup;
use std::{iter, net::SocketAddr};

fn missing(error: std::io::Error) -> std::io::Result<iter::Empty<SocketAddr>> {
    Err(error)
}

#[test]
fn system_dns_lookup_maps_definitive_windows_errors_to_negative_answers() {
    assert_eq!(
        classify_windows_dns_lookup(missing(std::io::Error::from(std::io::ErrorKind::NotFound))),
        Ok(None)
    );
    assert_eq!(
        classify_windows_dns_lookup(missing(std::io::Error::from_raw_os_error(11001))),
        Ok(None)
    );
    assert_eq!(
        classify_windows_dns_lookup(missing(std::io::Error::from_raw_os_error(11004))),
        Ok(None)
    );
    assert_eq!(
        classify_windows_dns_lookup(missing(std::io::Error::from_raw_os_error(11002))),
        Err(())
    );
}
