use unproxy::dns::parse_counts;
#[test]
fn dns_wire_parser_checks_declared_sections(){let mut b=vec![0u8;12];assert_eq!(parse_counts(&b).unwrap().answers,0);b[5]=1;assert!(parse_counts(&b).is_err());}
#[test]
fn dns_wire_parser_rejects_bad_compression(){let mut b=vec![0u8;18];b[5]=1;b[12]=0xc0;b[13]=0xff;assert!(parse_counts(&b).is_err());}
