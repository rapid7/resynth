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

## flow
```resynth
resynth fn flow (
    cl: Sock4,
    sv: Sock4,
    raw: bool = false,
) -> Obj;
```
 Create a UDP flow context, from which other packets can be created

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
