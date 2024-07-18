 # UDP Flow
## Index


### Functions

- [client_dgram](#client_dgram)
- [client_raw_dgram](#client_raw_dgram)
- [server_dgram](#server_dgram)
- [server_raw_dgram](#server_raw_dgram)



## client_dgram
```resynth
resynth fn client_dgram (
    frag_off: u16 = 0x0000,
    csum: bool = true,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Send a datagram from client to server

## client_raw_dgram
```resynth
resynth fn client_raw_dgram (
    csum: bool = true,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Return a datagram from client to server (minus IP header)

## server_dgram
```resynth
resynth fn server_dgram (
    frag_off: u16 = 0x0000,
    csum: bool = true,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Send a datagram from server to client

## server_raw_dgram
```resynth
resynth fn server_raw_dgram (
    csum: bool = true,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Return a datagram from server to client (minus IP header)
