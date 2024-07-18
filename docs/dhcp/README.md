 # DHCP / BOOTP
## Index


### Modules

- [msgtype](msgtype/README.md)
- [opcode](opcode/README.md)
- [opt](opt/README.md)

### Functions

- [hdr](#hdr)
- [option](#option)

### Constants

| Name | Value |
| ---- | ----- |
| CLIENT_PORT | `(u16)0x0044` |
| SERVER_PORT | `(u16)0x0043` |



## hdr
```resynth
resynth fn hdr (
    opcode: u8 = 0x01,
    htype: u8 = 0x01,
    hlen: u8 = 0x06,
    hops: u8 = 0x00,
    xid: u32 = 0x00000000,
    ciaddr: Ip4 = 0.0.0.0,
    yiaddr: Ip4 = 0.0.0.0,
    siaddr: Ip4 = 0.0.0.0,
    giaddr: Ip4 = 0.0.0.0,
    chaddr: type = Str,
    sname: type = Str,
    file: type = Str,
    magic: u32 = 0x63825363,
) -> bytes;
```
 DHCP header

## option
```resynth
resynth fn option (
    opt: u8,
    =>
    *collect_args: bytes,
) -> bytes;
```
 DHCP Option
