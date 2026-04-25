 # ERSPAN version 3
## Index


### Classes

- [Erspan3](Erspan3.md)

### Functions

- [session](#session)



## session
```resynth
resynth fn session (
    cl: Ip4,
    sv: Ip4,
    raw: bool = false,
    hwid: u32 = 0x00000000,
    sgt: u32 = 0x00000000,
    granularity: u32 = 0x00000000,
    direction: u32 = 0x00000000,
) -> Erspan3;
```
 Create an erspan3 session

| | Name | Type |
|-| ---- | ---- |
| arg | `cl` | `Ip4` |
| arg | `sv` | `Ip4` |
| opt | `raw` | `bool` |
| opt | `hwid` | `u32` |
| opt | `sgt` | `u32` |
| opt | `granularity` | `u32` |
| opt | `direction` | `u32` |
| returns | | [Erspan3](../erspan3/Erspan3.md) |
