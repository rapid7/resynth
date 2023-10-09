use crate::args::Args;
use crate::err::Error;
use crate::stdlib::dns::DNS_NAME;
use crate::val::{Val, ValDef};

/// Construct a root name
#[test]
fn test_name_root() -> Result<(), Error> {
    let ret = (DNS_NAME.exec)(Args::new(None, vec![Val::from(true)], vec![]))?;

    let buf: &[u8] = ret.as_ref();

    assert_eq!(buf, b"\x00");

    Ok(())
}

/// Construct an empty name
#[test]
fn test_name_nothing() -> Result<(), Error> {
    let ret = (DNS_NAME.exec)(Args::new(None, vec![Val::from(false)], vec![]))?;

    let buf: &[u8] = ret.as_ref();

    assert_eq!(buf, b"");

    Ok(())
}

/// Parse a name
#[test]
fn test_name_parse() -> Result<(), Error> {
    let ret = (DNS_NAME.exec)(Args::new(
        None,
        vec![Val::from(true)],
        vec![Val::from(ValDef::Str(b"www.google.com"))],
    ))?;

    let buf: &[u8] = ret.as_ref();

    assert_eq!(buf, b"\x03www\x06google\x03com\x00");

    Ok(())
}

/// Construct a single label
#[test]
fn test_single_label() -> Result<(), Error> {
    let ret = (DNS_NAME.exec)(Args::new(
        None,
        vec![Val::from(false)],
        vec![Val::from(ValDef::Str(b"com"))],
    ))?;

    let buf: &[u8] = ret.as_ref();

    assert_eq!(buf, b"\x03com");

    Ok(())
}
