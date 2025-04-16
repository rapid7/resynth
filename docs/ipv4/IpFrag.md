 # IP Packet Fragment Builder
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
