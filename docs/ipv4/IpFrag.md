 # IP Packet Fragment Builder

 Represents a single IP datagram that can be emitted either whole or split
 into multiple fragments. Create one with `ipv4::frag(src, dst, ..., payload)`,
 then emit fragments in the desired order:

 - `fragment(frag_off, len)` — emits a fragment with the MF (more-fragments) bit set
 - `tail(frag_off)` — emits the final fragment (MF clear), inferring the length
 - `datagram()` — emits the whole datagram unfragmented

 `frag_off` is in 8-byte units as per the IP specification. Fragments can be
 emitted out of order and with time gaps (using `time::jump_*`) to test
 reassembly timeout handling.
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [datagram](#datagram) | `Pkt` | Return the entire datagram as a single unfragmented packet |
| [fragment](#fragment) | `Pkt` | Return an IPv4 packet fragment with the MF (more-fragments) bit set |
| [tail](#tail) | `Pkt` | Return the final IPv4 fragment with MF=0 |



## datagram
```resynth
resynth fn datagram (
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Return the entire datagram as a single unfragmented packet

 Emits the full payload as one IPv4 packet with no fragmentation headers.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `raw` | `bool` | If true, omit the ethernet header _(default: `false`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |

## fragment
```resynth
resynth fn fragment (
    frag_off: u16,
    len: u16,
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Return an IPv4 packet fragment with the MF (more-fragments) bit set

 Slices the stored datagram at the given offset and length and wraps it in
 an IPv4 header with MF=1. Fragment offset is in units of 8 bytes as per RFC 791.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `frag_off` | `u16` | Fragment offset in 8-byte blocks |
| `len` | `u16` | Length of this fragment in bytes |
| `raw` | `bool` | If true, omit the ethernet header _(default: `false`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |

## tail
```resynth
resynth fn tail (
    frag_off: u16,
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Return the final IPv4 fragment with MF=0

 Convenience wrapper around [fragment](#fragment) for the last fragment in a
 series — the MF bit is cleared automatically so no `len` is required.

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `frag_off` | `u16` | Fragment offset in 8-byte blocks |
| `raw` | `bool` | If true, omit the ethernet header _(default: `false`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |
