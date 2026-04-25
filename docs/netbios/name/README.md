 # NetBIOS names
## Index


### Modules

| Module | Description |
| ------ | ----------- |
| [suffix](suffix/README.md) | NetBIOS name suffixes |

### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [encode](#encode) | `bytes` | First-level encode a NetBIOS name, including padding and the one-byte suffix field. |



## encode
```resynth
resynth fn encode (
    suffix: u8 = 0x00,
    =>
    *collect_args: bytes,
) -> bytes;
```
First-level encode a NetBIOS name, including padding and the one-byte suffix field.

 Returns the raw 32 encoded bytes only — no DNS label length prefix or
 terminating null byte. To produce a complete DNS-format name label
 suitable for use in an NBNS packet, wrap the result with `dns::name()`:

 ```resynth
 dns::name(netbios::name::encode("BILLG"))
 ```

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `suffix` | `u8` | One-byte suffix identifying the NetBIOS name type _(default: `0x00`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |
