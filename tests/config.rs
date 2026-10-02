use clap::Parser;
use unproxy::config::{MainArgs,token_file};
use std::{fs,path::PathBuf};
#[test]
fn defaults_and_listener_validation(){let a=MainArgs::try_parse_from(["unproxy"]).unwrap();assert_eq!(a.listen_addrs().unwrap()[0].to_string(),"127.0.0.1:3128");let a=MainArgs::try_parse_from(["unproxy","-L","[::1]:3128"]).unwrap();assert_eq!(a.listen_addrs().unwrap()[0].to_string(),"[::1]:3128");let a=MainArgs::try_parse_from(["unproxy","-L","0.0.0.0:80"]).unwrap();assert!(a.listen_addrs().is_err())}
#[test]
fn settings_are_whitespace_tokens(){let p=PathBuf::from(std::env::temp_dir()).join("unproxyrc-test");fs::write(&p,"# comment\n --listen 127.0.0.1:4567  \n\n--direct-fallback\n").unwrap();assert_eq!(token_file(&p),vec!["--listen","127.0.0.1:4567","--direct-fallback"]);let _=fs::remove_file(p);}
