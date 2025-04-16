 # Ethernet
## Index


### Modules

- [ethertype](ethertype/README.md)

### Functions

- [frame](#frame)
- [from_ip](#from_ip)

### Constants

| Name | Value |
| ---- | ----- |
| BROADCAST | `(bytes)"\xff\xff\xff\xff\xff\xff"` |



## frame
```resynth
resynth fn frame (
    src: bytes,
    dst: bytes,
    ethertype: u16 = 0x0800,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Ethernet Frame

 ### Arguments
 * `dst` Destination ethernet address as bytes
 * `src` Source ethernet address as bytes
 * `ethertype` [Ethertype](ethertype/README.md), defaults to IPV4
 * `*payload: Str` the payload bytes

## from_ip
```resynth
resynth fn from_ip (
    ip: Ip4,
) -> bytes;
```
 Map IPv4 address into ethernet address

 Right now you just get a locally administered IP address with the IP address as the last
 four octets

 ### Arguments
 * `ip` Ip address
