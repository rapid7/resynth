 # Internet Control Message Protocol (ICMP)
## Index


### Classes

- [Icmp](Icmp.md)

### Functions

- [flow](#flow)



## flow
```resynth
resynth fn flow (
    cl: Ip4,
    sv: Ip4,
    raw: bool = false,
) -> Icmp;
```
 Create an ICMP flow

| | Name | Type |
|-| ---- | ---- |
| arg | `cl` | `Ip4` |
| arg | `sv` | `Ip4` |
| opt | `raw` | `bool` |
| returns | | [Icmp](../../ipv4/icmp/Icmp.md) |
