use crate::netbios::name;

/// Test netbios name encode
#[test]
fn test_nb_encode() -> Result<(), ()> {
    let enc = name::encode(b"BILLG", 0).ok_or(())?;
    assert_eq!(b"ECEJEMEMEHCACACACACACACACACACAAA", enc.as_ref());
    Ok(())
}
