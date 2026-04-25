 # User Datagram Protocol (UDP)
## Index


### Classes

- [UdpFlow](UdpFlow.md)

### Functions

- [broadcast](#broadcast)
- [flow](#flow)
- [hdr](#hdr)
- [unicast](#unicast)



## broadcast
```resynth
resynth fn broadcast (
    src: Sock4,
    dst: Sock4,
    srcip: type = Ip4,
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Send a broadcast datagram

| | Name | Type |
|-| ---- | ---- |
| arg | `src` | `Sock4` |
| arg | `dst` | `Sock4` |
| opt | `srcip` | `type` |
| opt | `raw` | `bool` |
| collect | `*args` | `bytes` |
| returns | | `Pkt` |

## flow
```resynth
resynth fn flow (
    cl: Sock4,
    sv: Sock4,
    raw: bool = false,
) -> UdpFlow;
```
 Create a UDP flow context, from which other packets can be created

| | Name | Type |
|-| ---- | ---- |
| arg | `cl` | `Sock4` |
| arg | `sv` | `Sock4` |
| opt | `raw` | `bool` |
| returns | | [UdpFlow](../../ipv4/udp/UdpFlow.md) |

## hdr
```resynth
resynth fn hdr (
    src: u16,
    dst: u16,
    len: u16 = 0x0000,
    csum: u16 = 0x0000,
) -> bytes;
```
 Returns a UDP header (with no IP header)

| | Name | Type |
|-| ---- | ---- |
| arg | `src` | `u16` |
| arg | `dst` | `u16` |
| opt | `len` | `u16` |
| opt | `csum` | `u16` |
| returns | | `bytes` |

## unicast
```resynth
resynth fn unicast (
    src: Sock4,
    dst: Sock4,
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Send a unicast datagram

| | Name | Type |
|-| ---- | ---- |
| arg | `src` | `Sock4` |
| arg | `dst` | `Sock4` |
| opt | `raw` | `bool` |
| collect | `*args` | `bytes` |
| returns | | `Pkt` |
