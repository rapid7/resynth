 # VXLAN Encapsulation

 Encapsulates ethernet frames in [UDP](../ipv4/udp/README.md) datagrams.
## Index


### Classes

- [Vxlan](Vxlan.md)

### Functions

- [session](#session)

### Constants

| Name | Value |
| ---- | ----- |
| DEFAULT_PORT | `(u16)0x12b5` |



## session
```resynth
resynth fn session (
    cl: Sock4,
    sv: Sock4,
    sessionid: u32 = 0x00000000,
    raw: bool = false,
) -> Vxlan;
```
 Create a VXLAN session

| | Name | Type |
|-| ---- | ---- |
| arg | `cl` | `Sock4` |
| arg | `sv` | `Sock4` |
| opt | `sessionid` | `u32` |
| opt | `raw` | `bool` |
| returns | | [Vxlan](../vxlan/Vxlan.md) |
