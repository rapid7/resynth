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

## name
```resynth
resynth fn name (
    complete: bool = true,
    =>
    *collect_args: bytes,
) -> bytes;
```
 A DNS name encoded with length prefixes

## pointer
```resynth
resynth fn pointer (
    offset: u16 = 0x000c,
) -> bytes;
```
 A DNS compression pointer

## question
```resynth
resynth fn question (
    qname: bytes,
    qtype: u16 = 0x0001,
    qclass: u16 = 0x0001,
) -> bytes;
```
 A DNS question
