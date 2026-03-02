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
) -> Obj;
```
 Create an erspan3 session
