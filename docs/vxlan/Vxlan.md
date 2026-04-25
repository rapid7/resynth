 # VXLAN Session
## Index


### Functions

- [dgram](#dgram)
- [encap](#encap)



## dgram
```resynth
resynth fn dgram (
    pkt: Pkt,
) -> Pkt;
```
 Encapsulate a single packet

| | Name | Type |
|-| ---- | ---- |
| arg | `pkt` | `Pkt` |
| returns | | `Pkt` |

## encap
```resynth
resynth fn encap (
    it: PktGen,
) -> PktGen;
```
 Encapsulate a series of packets

| | Name | Type |
|-| ---- | ---- |
| arg | `it` | `PktGen` |
| returns | | `PktGen` |
