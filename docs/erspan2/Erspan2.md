 # ERSPAN2 Session
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [encap](#encap) | `PktGen` | Encapsulate packets in ERSPAN2 |



## encap
```resynth
resynth fn encap (
    it: PktGen,
    port_index: u32 = 0x00000000,
) -> PktGen;
```
Encapsulate packets in ERSPAN2

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `it` | `PktGen` | Sequence of packets to encapsulate |
| `port_index` | `u32` | ERSPAN port index (identifies the source port) _(default: `0x00000000`)_ |

### Returns

| Type |
| ---- |
| `PktGen` |
