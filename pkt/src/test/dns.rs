use crate::dns::DnsName;

/// Construct a root name
#[test]
fn test_name_root() {
    let n = DnsName::root();
    assert_eq!(b"\x00", n.as_ref());
}

/// Construct a compression pointer
#[test]
fn test_ptr() {
    let n = DnsName::compression_pointer(0x4bad);
    assert_eq!(b"\xcb\xad", n.as_ref());
}

/// Partial name construction
#[test]
fn test_partial() {
    let mut n = DnsName::new();
    n.push(b"www");
    n.push(b"evildoer");
    n.push(b"n3t");
    assert_eq!(b"\x03www\x08evildoer\x03n3t", n.as_ref());
}

/// Partial name construction
#[test]
fn test_complete() {
    let mut n = DnsName::new();
    n.push(b"www");
    n.push(b"evildoer");
    n.push(b"n3t");
    n.finish();
    assert_eq!(b"\x03www\x08evildoer\x03n3t\x00", n.as_ref());
}

/// Name parsing
#[test]
fn test_parse() {
    let n = DnsName::from(b"www.evildoer.n3t");
    assert_eq!(b"\x03www\x08evildoer\x03n3t\x00", n.as_ref());
}

/// Name parsing with a final dot
/// To be honest, we should probably detect and ignore that final dot?
#[test]
fn test_trailing_dot() {
    let n = DnsName::from(b"www.evildoer.n3t.");
    assert_eq!(b"\x03www\x08evildoer\x03n3t\x00\x00", n.as_ref());
}

/// Pushing raw bytes
#[test]
fn test_push_raw() {
    let mut n = DnsName::new();
    n.push(b"www");
    n.push(b"evildoer");
    n.push(b"n3t");
    n.push_raw(b"\xf0\x0f");
    n.finish();
    assert_eq!(b"\x03www\x08evildoer\x03n3t\xf0\x0f\x00", n.as_ref());
}
