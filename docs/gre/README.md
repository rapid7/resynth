 # Generic Routing Encapsulation (GRE)

 Right now this exists only for GRETAP [sessions](#session)
## Index


### Classes

- [Gre](Gre.md)

### Functions

- [session](#session)



## session
```resynth
resynth fn session (
    cl: Ip4,
    sv: Ip4,
    ethertype: u16,
    raw: bool = false,
) -> Obj;
```
 Create a GRETAP session
