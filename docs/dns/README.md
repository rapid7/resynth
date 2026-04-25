 # Domain Name System

 You can use [host](#host) to do simple DNS requests

 Or you can use the other functions to build custom DNS messages
## Index


### Modules

- [class](class/README.md)
- [opcode](opcode/README.md)
- [qtype](qtype/README.md)
- [rcode](rcode/README.md)
- [rtype](rtype/README.md)

### Functions

- [answer](#answer)
- [flags](#flags)
- [hdr](#hdr)
- [host](#host)
- [name](#name)
- [pointer](#pointer)
- [question](#question)



## answer
```resynth
resynth fn answer (
    aname: bytes,
    atype: u16 = 0x0001,
    aclass: u16 = 0x0001,
    ttl: u32 = 0x000000e5,
    =>
    *collect_args: bytes,
) -> bytes;
```
 A DNS answer (RR)

| | Name | Type |
|-| ---- | ---- |
| arg | `aname` | `bytes` |
| opt | `atype` | `u16` |
| opt | `aclass` | `u16` |
| opt | `ttl` | `u32` |
| collect | `*args` | `bytes` |
| returns | | `bytes` |

## flags
```resynth
resynth fn flags (
    opcode: u8,
    response: bool = false,
    aa: bool = false,
    tc: bool = false,
    rd: bool = false,
    ra: bool = false,
    z: bool = false,
    ad: bool = false,
    cd: bool = false,
    rcode: u8 = 0x00,
) -> u16;
```
 a DNS flags field

| | Name | Type |
|-| ---- | ---- |
| arg | `opcode` | `u8` |
| opt | `response` | `bool` |
| opt | `aa` | `bool` |
| opt | `tc` | `bool` |
| opt | `rd` | `bool` |
| opt | `ra` | `bool` |
| opt | `z` | `bool` |
| opt | `ad` | `bool` |
| opt | `cd` | `bool` |
| opt | `rcode` | `u8` |
| returns | | `u16` |

## hdr
```resynth
resynth fn hdr (
    id: u16,
    flags: u16,
    qdcount: u16 = 0x0000,
    ancount: u16 = 0x0000,
    nscount: u16 = 0x0000,
    arcount: u16 = 0x0000,
) -> bytes;
```
 A DNS header

| | Name | Type |
|-| ---- | ---- |
| arg | `id` | `u16` |
| arg | `flags` | `u16` |
| opt | `qdcount` | `u16` |
| opt | `ancount` | `u16` |
| opt | `nscount` | `u16` |
| opt | `arcount` | `u16` |
| returns | | `bytes` |

## host
```resynth
resynth fn host (
    client: Ip4,
    qname: bytes,
    ttl: u32 = 0x000000e5,
    ns: Ip4 = 1.1.1.1,
    raw: bool = false,
    =>
    *collect_args: Ip4,
) -> PktGen;
```
 Perform a DNS lookup, with response

| | Name | Type |
|-| ---- | ---- |
| arg | `client` | `Ip4` |
| arg | `qname` | `bytes` |
| opt | `ttl` | `u32` |
| opt | `ns` | `Ip4` |
| opt | `raw` | `bool` |
| collect | `*args` | `Ip4` |
| returns | | `PktGen` |

## name
```resynth
resynth fn name (
    complete: bool = true,
    =>
    *collect_args: bytes,
) -> bytes;
```
 A DNS name encoded with length prefixes

| | Name | Type |
|-| ---- | ---- |
| opt | `complete` | `bool` |
| collect | `*args` | `bytes` |
| returns | | `bytes` |

## pointer
```resynth
resynth fn pointer (
    offset: u16 = 0x000c,
) -> bytes;
```
 A DNS compression pointer

| | Name | Type |
|-| ---- | ---- |
| opt | `offset` | `u16` |
| returns | | `bytes` |

## question
```resynth
resynth fn question (
    qname: bytes,
    qtype: u16 = 0x0001,
    qclass: u16 = 0x0001,
) -> bytes;
```
 A DNS question

| | Name | Type |
|-| ---- | ---- |
| arg | `qname` | `bytes` |
| opt | `qtype` | `u16` |
| opt | `qclass` | `u16` |
| returns | | `bytes` |
