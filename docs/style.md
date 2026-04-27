# Resynth Style Guide

Rules and conventions for writing readable, maintainable `.rsyn` files.

---

## Guiding Principle

A `.rsyn` file is documentation of a network exchange. A reader should
be able to understand what protocol behaviour is being described without
cross-referencing a hex dump or an RFC. Encode intent, not just bytes.

---

## File Structure

A typical `.rsyn` file follows this order:

1. **Header comment** — one or two lines describing the scenario
2. **Imports** — only what you use
3. **Flow setup** — `let flow = ipv4::tcp::flow(...)`
4. **Traffic** — `flow.client_message(...)`, `flow.server_message(...)`

```resynth
// SMTP banner with STARTTLS upgrade
import ipv4;
import text;

let flow = ipv4::tcp::flow(
  192.168.1.10/54321,
  10.0.0.1/1234,
);

flow.server_message("220 smtp.example.com ESMTP", text::CRLF);
flow.client_message("STARTTLS", text::CRLF);
flow.server_message("220 Ready to start TLS", text::CRLF);
```

Common imports:

```resynth
import ipv4;     // flows and datagrams (almost always needed)
import std;      // encoding functions (any binary protocol)
import text;     // text::CRLF, text::crlflines (text protocols)
import dns;      // DNS-specific helpers
import tls;      // TLS-specific helpers
```

---

## Whitespace and Formatting

- **Indentation:** 2 spaces. No tabs.
- **Line length:** 100 columns maximum.
- **Argument lists:** when a call exceeds one line, put each argument
  on its own line, indented by 2 spaces:

```resynth
flow.client_message(
  std::be16(0x0003),
  std::len_be16(
    adjust: 4,
    std::be16(0x0001),
    "payload data",
  ),
);
```

---

## Use Stdlib Helpers for All Structured Fields

Every multi-byte numeric field must use `std::be16()`, `std::le32()`,
etc. — not raw hex. The reader cannot tell byte order, field width, or
semantic intent from `"|00 04 00 1c|"`.

```resynth
// Bad — opaque, byte order unclear
"|00 04 00 1c 03 00 00 00|"

// Good — self-documenting
std::be16(4),             // hlen
std::be16(0x1c),          // flags
std::le32(3),             // version
```

When a protocol-specific module exists (dns, tls, netbios, dhcp, etc.),
use its helpers instead of raw `std::` calls:

```resynth
// Bad — manual DNS header
std::be16(0x1234),        // id
std::be16(0x0100),        // flags
std::be16(1),             // qdcount
std::be16(0),             // ancount
std::be16(0),             // nscount
std::be16(0),             // arcount

// Good — dns:: helper handles the structure
dns::hdr(
  id: 0x1234,
  flags: dns::flags(opcode: dns::opcode::QUERY, rd: true),
  qdcount: 1,
),
```

**Run `resynth --output-stdlib-json`** before writing any `.rsyn` file
to discover available helpers. Search for the protocol name and for
structurally related protocols.

---

## When Hex Blobs Are Acceptable

Raw hex is appropriate only for genuinely opaque or unstructured data:

- **Encrypted payloads** — TLS application data, Kerberos ciphertext
- **Binary certificates and ASN.1/BER** — no resynth helpers exist for
  ASN.1 encoding
- **Pre-computed digests and authenticators** — HMAC values, RADIUS
  authenticator
- **Padding and reserved fields** — `"|00 00 00|"` for 3-byte padding
- **Bit-packed fields** with no clean decomposition — comment what the
  bits mean
- **3-byte lengths** — no `std::be24()` exists; use hex with a comment

When using hex blobs, **always add a comment** explaining the content:

```resynth
"|78 56 34 12 cd ab ef 00|",   // UUID: 12345678-abcd-00ef...
"|00 00 00|",                   // padding (3 bytes)
"|a0 03 02 01 05|",            // ASN.1: [0] { INTEGER 5 }
```

### Large hex blobs

Format at **16 bytes per line**. This matches standard hexdump
conventions and hex editor layouts, making it easy to count offsets
and cross-reference with tools like `xxd` or `cadmium hexdump`:

```resynth
  "|b6 02 bd f4 e8 0e cf c6 1d 1b 48 49 59 e0 2b ef|"
  "|e9 4b 1f 2d c8 69 f4 7d 7a e0 00 27 9c 26 f9 c1|"
```

---

## Inline Hex Escapes — Never Unnecessarily Split

Hex escapes go **inside** the string they belong to. Do not
unnecessarily split a string and its hex escape into separate adjacent
literals:

```resynth
// Bad — unnecessary split
"SSH-2.0-OpenSSH" "|0d 0a|"

// Good — hex inline in the string
"SSH-2.0-OpenSSH|0d 0a|"

// Also good — use text::CRLF for readability
"SSH-2.0-OpenSSH", text::CRLF,
```

---

## Use `text::CRLF` for Line Terminators

For text protocols, prefer `text::CRLF` over raw `|0d 0a|`. It's
self-documenting and makes line boundaries visible at a glance.

For multi-line exchanges, `text::crlflines()` is even cleaner:

```resynth
// Acceptable
"EHLO example.com|0d 0a|"

// Better
"EHLO example.com", text::CRLF,

// Best for multi-line
text::crlflines(
  "220 smtp.example.com ESMTP",
  "EHLO example.com",
  text::CRLF,
),
```

---

## Commas and String Pasting

Adjacent string literals paste together automatically — no comma:

```resynth
"hello " "world"          // → "hello world"
"SSH-2.0|0d 0a|"          // → one string with embedded CRLF
```

A `std::` call (or any function call) is **not** a string literal. It
must be comma-separated from its neighbours:

```resynth
// Wrong — missing commas around std:: call
"magic"
std::be16(0x0001)
"|00 08|"

// Right
"magic",
std::be16(0x0001),
"|00 08|",
```

**Rule of thumb:** comma before and after every function call in a
collect-arg list. Omit commas only between adjacent string literals
you want pasted.

---

## Breaking Long Strings

Split at **meaningful token boundaries**. The delimiter or separator
stays with what follows it, not what precedes it:

```resynth
// Bad — delimiter stranded at end of first fragment
"Location:http://example.com/udhisapi.dll?"
"content=uuid:11a6f064-4791-4477-a680-e0b3ce8c79c3",

// Good — delimiter leads the next fragment
"Location:http://example.com/udhisapi.dll"
"?content=uuid:11a6f064-4791-4477-a680-e0b3ce8c79c3",

// Bad — breaks mid-token
"{|22|request|22|:|22|active checks|22|,|22|host|22|:|22|Test-ag"
"ent|22|}"

// Good — breaks at JSON comma boundary
"{|22|request|22|:|22|active checks|22|,"
"|22|host|22|:|22|Test-agent|22|}"
```

---

## Comments

Add a brief inline comment to each field identifying what it is:

```resynth
flow.client_message(
  std::u8(5),                      // rpc_vers
  std::u8(0),                      // rpc_vers_minor
  std::u8(0x0b),                   // ptype: bind
  std::u8(0x03),                   // flags: first+last
  "|00 00 00 10|",                 // data_repr: big-endian
  std::be16(0x0048),               // frag_length: 72
);
```

For a file header comment, one or two lines explaining the scenario:

```resynth
// DCERPC bind with big-endian byte order
// Covers: dcerpc.c lines 45-46 (big-endian u16 conversion)
```

Don't over-comment obvious things. `// padding` on `"|00 00|"` is
useful. `// this sends a message` on `flow.client_message()` is not.

---

## Endianness

Match the protocol's wire byte order — this varies per protocol and
sometimes within a single protocol:

| Protocol family | Byte order |
|----------------|------------|
| IP, TCP, UDP, DNS, SSH, STUN, RADIUS, RTCP, CAPWAP | Big-endian (`std::be*`) |
| SMB2, MySQL, RDP user data blocks | Little-endian (`std::le*`) |
| DCERPC | Per-packet — check the `data_repr` field |
| RDP | Mixed — TPKT/X.224/T.125 are BE, user data is LE |

When a protocol uses mixed endianness, comment which byte order applies
to each section.
