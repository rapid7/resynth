 # Internet Protocol Version 4
## Index


### Modules

- [icmp](icmp/README.md)
- [proto](proto/README.md)
- [tcp](tcp/README.md)
- [udp](udp/README.md)

### Classes

- [IpFrag](IpFrag.md)

### Functions

- [datagram](#datagram)
- [frag](#frag)



## datagram
```resynth
resynth fn datagram (
    src: Ip4,
    dst: Ip4,
    id: u16 = 0x0000,
    evil: bool = false,
    df: bool = false,
    mf: bool = false,
    ttl: u8 = 0x40,
    frag_off: u16 = 0x0000,
    proto: u8 = 0x11,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Create a raw IPv4 header or datagram

## frag
```resynth
resynth fn frag (
    src: Ip4,
    dst: Ip4,
    id: u16 = 0x0000,
    evil: bool = false,
    df: bool = false,
    ttl: u8 = 0x40,
    proto: u8 = 0x11,
    =>
    *collect_args: bytes,
) -> Obj;
```
 Create a context for a packet which can be arbitrarily fragmented
