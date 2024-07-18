 # TCP Connection
## Index


### Functions

- [client_ack](#client_ack)
- [client_close](#client_close)
- [client_hdr](#client_hdr)
- [client_hole](#client_hole)
- [client_message](#client_message)
- [client_raw_segment](#client_raw_segment)
- [client_reset](#client_reset)
- [client_segment](#client_segment)
- [open](#open)
- [server_ack](#server_ack)
- [server_close](#server_close)
- [server_hdr](#server_hdr)
- [server_hole](#server_hole)
- [server_message](#server_message)
- [server_raw_segment](#server_raw_segment)
- [server_reset](#server_reset)
- [server_segment](#server_segment)



## client_ack
```resynth
resynth fn client_ack (
    seq: type = U32,
    ack: type = U32,
) -> Pkt;
```
 Sends an ACK from the client

## client_close
```resynth
resynth fn client_close (
) -> PktGen;
```
 Shutdown both sides of the TCP connection, with the client sending the first FIN

## client_hdr
```resynth
resynth fn client_hdr (
    bytes: u32 = 0x00000000,
) -> bytes;
```
 Returns only the TCP header, from client to server

## client_hole
```resynth
resynth fn client_hole (
    bytes: u32,
) -> void;
```
 Creates a hole in the sever's Tx sequence space, making it look like we missed a packet
 from the client

## client_message
```resynth
resynth fn client_message (
    send_ack: bool = true,
    seq: type = U32,
    ack: type = U32,
    frag_off: u16 = 0x0000,
    =>
    *collect_args: bytes,
) -> PktGen;
```
 Sends a message from client to server, may also send an ACK in response

## client_raw_segment
```resynth
resynth fn client_raw_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Returns a single segment, minus the IP header, from client to server

## client_reset
```resynth
resynth fn client_reset (
) -> Pkt;
```
 Send a RST packet from the client

## client_segment
```resynth
resynth fn client_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Returns a single segment from client to server

## open
```resynth
resynth fn open (
) -> PktGen;
```
 Performs a TCP 3-way handshake

## server_ack
```resynth
resynth fn server_ack (
    seq: type = U32,
    ack: type = U32,
) -> Pkt;
```
 Sends an ACK from the server

## server_close
```resynth
resynth fn server_close (
) -> PktGen;
```
 Shutdown both sides of the TCP connection, with the server sending the first FIN

## server_hdr
```resynth
resynth fn server_hdr (
    bytes: u32 = 0x00000000,
) -> bytes;
```
 Returns only the TCP header, from server to client

## server_hole
```resynth
resynth fn server_hole (
    bytes: u32,
) -> void;
```
 Creates a hole in the sever's Tx sequence space, making it look like we missed a packet
 from the server

## server_message
```resynth
resynth fn server_message (
    send_ack: bool = true,
    seq: type = U32,
    ack: type = U32,
    frag_off: u16 = 0x0000,
    =>
    *collect_args: bytes,
) -> PktGen;
```
 Sends a message from server to client, may also send an ACK in response

## server_raw_segment
```resynth
resynth fn server_raw_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Returns a single segment, minus the IP header, from server to client

## server_reset
```resynth
resynth fn server_reset (
) -> Pkt;
```
 Send a RST packet from the server

## server_segment
```resynth
resynth fn server_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Returns a single segment from server to client
