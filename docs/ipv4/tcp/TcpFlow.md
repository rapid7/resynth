 # TCP Connection

 Represents a TCP flow between a client and server socket address. The
 flow tracks sequence and acknowledgement numbers automatically.

 ## Method overview

 | Method | Returns | Description |
 |--------|---------|-------------|
 | `open` | `PktGen` | Full 3-way handshake |
 | `client_message` / `server_message` | `PktGen` | Data segment(s) + optional auto-ACK; advances sequence numbers |
 | `client_segment` / `server_segment` | `Pkt` | Single data segment, no auto-ACK; advances sequence numbers |
 | `client_raw_segment` / `server_raw_segment` | `bytes` | TCP+payload bytes only (no IP header); use with `ipv4::frag` |
 | `client_hdr` / `server_hdr` | `bytes` | TCP header only (no IP header, no payload); use with `ipv4::frag` |
 | `client_ack` / `server_ack` | `Pkt` | Bare ACK packet |
 | `client_hole` / `server_hole` | `void` | Advance sequence number without emitting a packet, simulating a missing segment |
 | `client_close` / `server_close` | `PktGen` | Full FIN/ACK/FIN/ACK teardown |
 | `client_reset` / `server_reset` | `Pkt` | RST packet |
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

| | Name | Type |
|-| ---- | ---- |
| opt | `seq` | `type` |
| opt | `ack` | `type` |
| returns | | `Pkt` |

## client_close
```resynth
resynth fn client_close (
) -> PktGen;
```
 Shutdown both sides of the TCP connection, with the client sending the first FIN

| | Name | Type |
|-| ---- | ---- |
| returns | | `PktGen` |

## client_hdr
```resynth
resynth fn client_hdr (
    bytes: u32 = 0x00000000,
) -> bytes;
```
 Returns a TCP header only (no payload, no IP header) for a
 client-to-server segment, as `bytes`. The optional `bytes` argument
 declares how many payload bytes the header should account for in the
 sequence number, without actually emitting them. Use with `ipv4::frag`
 to craft fragmented packets where the TCP header lands in one fragment
 and the payload in another.

| | Name | Type |
|-| ---- | ---- |
| opt | `bytes` | `u32` |
| returns | | `bytes` |

## client_hole
```resynth
resynth fn client_hole (
    bytes: u32,
) -> void;
```
 Creates a hole in the sever's Tx sequence space, making it look like we missed a packet
 from the client

| | Name | Type |
|-| ---- | ---- |
| arg | `bytes` | `u32` |

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
 Sends a message from client to server, advancing the sequence number.
 By default also emits an ACK from the server in response (`send_ack: true`).
 Use `send_ack: false` to suppress the ACK, for example when building
 out-of-order or reassembly test cases.

| | Name | Type |
|-| ---- | ---- |
| opt | `send_ack` | `bool` |
| opt | `seq` | `type` |
| opt | `ack` | `type` |
| opt | `frag_off` | `u16` |
| collect | `*args` | `bytes` |
| returns | | `PktGen` |

## client_raw_segment
```resynth
resynth fn client_raw_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Returns TCP header + payload bytes only (no Ethernet or IP header) for
 a client-to-server segment, advancing the sequence number. Returns
 `bytes` rather than `Pkt`. Use this with `ipv4::frag` to build
 IP-fragmented TCP segments.

| | Name | Type |
|-| ---- | ---- |
| opt | `seq` | `type` |
| opt | `ack` | `type` |
| collect | `*args` | `bytes` |
| returns | | `bytes` |

## client_reset
```resynth
resynth fn client_reset (
) -> Pkt;
```
 Send a RST packet from the client

| | Name | Type |
|-| ---- | ---- |
| returns | | `Pkt` |

## client_segment
```resynth
resynth fn client_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Returns a single data segment from client to server, advancing the
 sequence number. Does not emit an ACK. Returns a `Pkt` (complete
 Ethernet+IP+TCP packet) rather than a `PktGen`.

| | Name | Type |
|-| ---- | ---- |
| opt | `seq` | `type` |
| opt | `ack` | `type` |
| collect | `*args` | `bytes` |
| returns | | `Pkt` |

## open
```resynth
resynth fn open (
) -> PktGen;
```
 Performs a TCP 3-way handshake

| | Name | Type |
|-| ---- | ---- |
| returns | | `PktGen` |

## server_ack
```resynth
resynth fn server_ack (
    seq: type = U32,
    ack: type = U32,
) -> Pkt;
```
 Sends an ACK from the server

| | Name | Type |
|-| ---- | ---- |
| opt | `seq` | `type` |
| opt | `ack` | `type` |
| returns | | `Pkt` |

## server_close
```resynth
resynth fn server_close (
) -> PktGen;
```
 Shutdown both sides of the TCP connection, with the server sending the first FIN

| | Name | Type |
|-| ---- | ---- |
| returns | | `PktGen` |

## server_hdr
```resynth
resynth fn server_hdr (
    bytes: u32 = 0x00000000,
) -> bytes;
```
 Returns a TCP header only (no payload, no IP header) for a
 server-to-client segment, as `bytes`. The optional `bytes` argument
 declares how many payload bytes the header should account for in the
 sequence number, without actually emitting them. Use with `ipv4::frag`
 to craft fragmented packets where the TCP header lands in one fragment
 and the payload in another.

| | Name | Type |
|-| ---- | ---- |
| opt | `bytes` | `u32` |
| returns | | `bytes` |

## server_hole
```resynth
resynth fn server_hole (
    bytes: u32,
) -> void;
```
 Creates a hole in the sever's Tx sequence space, making it look like we missed a packet
 from the server

| | Name | Type |
|-| ---- | ---- |
| arg | `bytes` | `u32` |

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
 Sends a message from server to client, advancing the sequence number.
 By default also emits an ACK from the client in response (`send_ack: true`).
 Use `send_ack: false` to suppress the ACK, for example when building
 out-of-order or reassembly test cases.

| | Name | Type |
|-| ---- | ---- |
| opt | `send_ack` | `bool` |
| opt | `seq` | `type` |
| opt | `ack` | `type` |
| opt | `frag_off` | `u16` |
| collect | `*args` | `bytes` |
| returns | | `PktGen` |

## server_raw_segment
```resynth
resynth fn server_raw_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Returns TCP header + payload bytes only (no Ethernet or IP header) for
 a server-to-client segment, advancing the sequence number. Returns
 `bytes` rather than `Pkt`. Use this with `ipv4::frag` to build
 IP-fragmented TCP segments.

| | Name | Type |
|-| ---- | ---- |
| opt | `seq` | `type` |
| opt | `ack` | `type` |
| collect | `*args` | `bytes` |
| returns | | `bytes` |

## server_reset
```resynth
resynth fn server_reset (
) -> Pkt;
```
 Send a RST packet from the server

| | Name | Type |
|-| ---- | ---- |
| returns | | `Pkt` |

## server_segment
```resynth
resynth fn server_segment (
    seq: type = U32,
    ack: type = U32,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Returns a single data segment from server to client, advancing the
 sequence number. Does not emit an ACK. Returns a `Pkt` (complete
 Ethernet+IP+TCP packet) rather than a `PktGen`.

| | Name | Type |
|-| ---- | ---- |
| opt | `seq` | `type` |
| opt | `ack` | `type` |
| collect | `*args` | `bytes` |
| returns | | `Pkt` |
