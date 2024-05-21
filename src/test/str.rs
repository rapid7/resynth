use crate::str::Buf;
use std::str::FromStr;

#[test]
fn str_nohex() {
    let s = Buf::from_str(concat!(
        "!#$%&'()*+,-./", // " is not allowed
        "0123456789",
        ":;<=>?",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "[\\]^_`",
        "abcdefghijklmnopqrstuvwxyz",
        "{}~", // | is not allowed
    ))
    .expect("parse failed");

    assert_eq!(
        s.cow_buffer(),
        concat!(
            "!#$%&'()*+,-./",
            "0123456789",
            ":;<=>?",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "[\\]^_`",
            "abcdefghijklmnopqrstuvwxyz",
            "{}~",
        )
        .as_bytes(),
    )
}

#[test]
fn str_backslash() {
    let s = Buf::from_str("\\").expect("parse failed");

    assert_eq!(s.cow_buffer(), "\\".as_bytes(),)
}

#[test]
fn str_bin() {
    let s = Buf::from_str("|00 01 02|").expect("parse failed");

    assert_eq!(s.cow_buffer(), b"\x00\x01\x02",)
}
