use crate::lex::{Lexer, TokType, Token};
use crate::loc::Loc;
use std::borrow::Cow;

#[test]
fn lex_empty() {
    let mut lex = Lexer::default();

    let got = lex.line(1, "\n").expect("failed to lex");
    let expected: Vec<Token> = vec![];

    assert_eq!(got, expected,)
}

#[test]
fn lex_backslash() {
    let mut lex = Lexer::default();

    let got = lex.line(1, "\"\\\";").expect("failed to lex");
    let expected: Vec<Token> = vec![
        Token {
            loc: Loc::new(1, 4),
            typ: TokType::StringLiteral,
            val: Some(Cow::Borrowed("\\")),
        },
        Token {
            loc: Loc::new(1, 4),
            typ: TokType::SemiColon,
            val: None,
        },
    ];

    assert_eq!(got, expected,)
}

#[test]
fn lex_string_chars() {
    let mut lex = Lexer::default();

    let got = lex
        .line(
            1,
            concat!(
                "\"",
                "!#$%&'()*+,-./", // " is not allowed
                "0123456789",
                ":;<=>?",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "[\\]^_`",
                "abcdefghijklmnopqrstuvwxyz",
                "{}~", // | is not allowed
                "\";\n",
            ),
        )
        .expect("failed to lex");
    let expected: Vec<Token> = vec![
        Token {
            loc: Loc::new(1, 94),
            typ: TokType::StringLiteral,
            val: Some(Cow::Borrowed(concat!(
                "!#$%&'()*+,-./", // " is not allowed
                "0123456789",
                ":;<=>?",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "[\\]^_`",
                "abcdefghijklmnopqrstuvwxyz",
                "{}~", // | is not allowed
            ))),
        },
        Token {
            loc: Loc::new(1, 94),
            typ: TokType::SemiColon,
            val: None,
        },
    ];

    assert_eq!(got, expected,)
}

#[test]
fn lex_hex() {
    let mut lex = Lexer::default();

    let got = lex
        .line(1, "\"|78:24:af:23:f0:a9|\";")
        .expect("failed to lex");
    let expected: Vec<Token> = vec![
        Token {
            loc: Loc::new(1, 22),
            typ: TokType::StringLiteral,
            val: Some(Cow::Borrowed("|78:24:af:23:f0:a9|")),
        },
        Token {
            loc: Loc::new(1, 22),
            typ: TokType::SemiColon,
            val: None,
        },
    ];

    assert_eq!(got, expected,)
}
