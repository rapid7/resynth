 # VXLAN Session
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [dgram](#dgram) | `Pkt` | Encapsulate a single packet |
| [encap](#encap) | `PktGen` | Encapsulate a series of packets |



## dgram
```resynth
resynth fn dgram (
    pkt: Pkt,
) -> Pkt;
```
Encapsulate a single packet

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `pkt` | `Pkt` | Single packet to encapsulate |

### Returns

| Type |
| ---- |
| `Pkt` |

## encap
```resynth
resynth fn encap (
    it: PktGen,
) -> PktGen;
```
Encapsulate a series of packets

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `it` | `PktGen` | Sequence of packets to encapsulate |

### Returns

| Type |
| ---- |
| `PktGen` |
