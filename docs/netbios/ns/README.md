 # NetBIOS Name Service
## Index


### Modules

- [opcode](opcode/README.md)
- [rcode](rcode/README.md)
- [rrtype](rrtype/README.md)

### Functions

- [flags](#flags)



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
    b: bool = false,
    rcode: u8 = 0x00,
) -> u16;
```
 Returns netbios-ns flags
