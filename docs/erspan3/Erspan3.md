 # ERSPAN3 Session
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [encap](#encap) | `PktGen` | Encapsulate packets in ERSPAN3 |



## encap
```resynth
resynth fn encap (
    it: PktGen,
    timestamp: u32 = 0x00000000,
) -> PktGen;
```
Encapsulate packets in ERSPAN3

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `it` | `PktGen` | Sequence of packets to encapsulate |
| `timestamp` | `u32` | ERSPAN timestamp value to embed in the header _(default: `0x00000000`)_ |

### Returns

| Type |
| ---- |
| `PktGen` |
