 # NetBIOS Name Service
## Index


### Modules

| Module | Description |
| ------ | ----------- |
| [opcode](opcode/README.md) | NetBIOS Name Service Opcodes |
| [rcode](rcode/README.md) | NetBIOS Name Service Response codes |
| [rrtype](rrtype/README.md) | NetBIOS Name Service RR types |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [flags](#flags) | `u16` | Returns netbios-ns flags |



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

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `opcode` | `u8` | NetBIOS name service opcode |
| `response` | `bool` | If true, this is a response; if false, a query _(default: `false`)_ |
| `aa` | `bool` | Authoritative Answer flag _(default: `false`)_ |
| `tc` | `bool` | Truncation flag _(default: `false`)_ |
| `rd` | `bool` | Recursion Desired flag _(default: `false`)_ |
| `ra` | `bool` | Recursion Available flag _(default: `false`)_ |
| `z` | `bool` | Reserved (Z) bit _(default: `false`)_ |
| `ad` | `bool` | Must be zero (maps to DNS AD bit) _(default: `false`)_ |
| `b` | `bool` | Broadcast/multicast flag _(default: `false`)_ |
| `rcode` | `u8` | Response code _(default: `0x00`)_ |

### Returns

| Type |
| ---- |
| `u16` |
