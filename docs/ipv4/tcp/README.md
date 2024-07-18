 # Transmission Control Protocol (TCP)
## Index


### Classes

- [TcpFlow](TcpFlow.md)

### Functions

- [flow](#flow)



## flow
```resynth
resynth fn flow (
    cl: Sock4,
    sv: Sock4,
    cl_seq: u32 = 0x00000001,
    sv_seq: u32 = 0x00000001,
    raw: bool = false,
) -> Obj;
```
 Create a [TCP flow context](TcpFlow.md), from which packets can be created
