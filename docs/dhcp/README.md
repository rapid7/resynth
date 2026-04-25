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

| | Name | Type |
|-| ---- | ---- |
| opt | `opcode` | `u8` |
| opt | `htype` | `u8` |
| opt | `hlen` | `u8` |
| opt | `hops` | `u8` |
| opt | `xid` | `u32` |
| opt | `ciaddr` | `Ip4` |
| opt | `yiaddr` | `Ip4` |
| opt | `siaddr` | `Ip4` |
| opt | `giaddr` | `Ip4` |
| opt | `chaddr` | `type` |
| opt | `sname` | `type` |
| opt | `file` | `type` |
| opt | `magic` | `u32` |
| returns | | `bytes` |

## option
```resynth
resynth fn option (
    opt: u8,
    =>
    *collect_args: bytes,
) -> bytes;
```
 DHCP Option

| | Name | Type |
|-| ---- | ---- |
| arg | `opt` | `u8` |
| collect | `*args` | `bytes` |
| returns | | `bytes` |
