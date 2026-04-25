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

- [datagram](#datagram)
- [fragment](#fragment)
- [tail](#tail)



## datagram
```resynth
resynth fn datagram (
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Return the entire datagram without fragmenting it

 ### Arguments
 * 'raw' If true, then omit ethernet header

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
 Returns an IPv4 packet fragment

 ### Arguments
 * `frag_off` Offset in 8-byte blocks
 * `len` Length in bytes
 * 'raw' If true, then omit ethernet header

## tail
```resynth
resynth fn tail (
    frag_off: u16,
    raw: bool = false,
    =>
    *collect_args: bytes,
) -> Pkt;
```
 Returns an IPv4 tail-fragment, ie. with MF (more-fragments) bit set to zero.
 This is just a convenience function which omits the len parameter.

 ### Arguments
 * `frag_off` Offset in 8-byte blocks
 * 'raw' If true, then omit ethernet header
