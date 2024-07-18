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

## encap
```resynth
resynth fn encap (
    gen: PktGen,
) -> PktGen;
```
 Encapsulate a series of packets
