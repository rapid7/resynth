use std::fmt;
use std::rc::Rc;
use std::str::FromStr;

#[derive(Clone)]
pub(crate) struct BytesObj {
    inner: Rc<Vec<u8>>,
}

impl AsRef<[u8]> for BytesObj {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl BytesObj {
    pub fn new(mut s: Vec<u8>) -> Self {
        s.shrink_to_fit();
        Self {
            inner: Rc::new(s),
        }
    }

    pub fn from(s: &[u8]) -> Self {
        Self {
            inner: Rc::new(s.to_owned()),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl fmt::Debug for BytesObj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /* TODO: allow printing of hex crap, data here does not have to be utf-8, and printing it
         * like this could panic.
         */
        let s = std::str::from_utf8(self.inner.as_ref()).unwrap();
        f.write_fmt(format_args!("Bytes<{:?}>", s))
    }
}

pub(crate) struct StringLiteralParseError {
}

fn hex_decode(chr: char) -> u8 {
    debug_assert!(chr.is_ascii_hexdigit());
    let c = chr as u8;
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => unreachable!()
    }
}

impl FromStr for BytesObj {
    type Err = StringLiteralParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = &s[1..s.len() - 1];
        let mut hex = false;
        let mut v: Vec<u8> = Vec::new();
        let mut h: [u8; 2] = [0, 0];
        let mut ix: usize = 0;

        for chr in inner.chars() {
            if !hex {
                if chr == '|' {
                    hex = true;
                    ix = 0;
                    continue;
                }
                v.push(chr as u8);
            } else {
                if chr.is_whitespace() {
                    continue;
                }

                if chr == '|' {
                    if ix != 0 {
                        /* Odd number of hex digits */
                        return Err(Self::Err {});
                    }

                    hex = false;
                    continue;
                }

                if !chr.is_ascii_hexdigit() {
                    /* Non-hex in hex sequence */
                    return Err(Self::Err {});
                }

                h[ix] = hex_decode(chr);
                ix += 1;
                if ix == 2 {
                    v.push((h[0] << 4) | h[1]);
                    ix = 0;
                }
            }
        }

        Ok(BytesObj::new(v))
    }
}