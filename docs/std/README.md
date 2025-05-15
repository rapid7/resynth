 # Standard types
## Index


### Functions

- [be16](#be16)
- [be32](#be32)
- [be64](#be64)
- [le16](#le16)
- [le32](#le32)
- [le64](#le64)
- [len_be16](#len_be16)
- [len_be32](#len_be32)
- [len_be64](#len_be64)
- [len_u8](#len_u8)
- [u8](#u8)



## be16
```resynth
resynth fn be16 (
    val: u64,
) -> bytes;
```
 Encode a 16bit integer into 2 big-endian bytes

## be32
```resynth
resynth fn be32 (
    val: u64,
) -> bytes;
```
 Encode a 32bit integer into 4 big-endian bytes

## be64
```resynth
resynth fn be64 (
    val: u64,
) -> bytes;
```
 Encode a 64bit integer into 8 big-endian bytes

## le16
```resynth
resynth fn le16 (
    val: u64,
) -> bytes;
```
 Encode a 16bit integer into 2 little-endian bytes

## le32
```resynth
resynth fn le32 (
    val: u64,
) -> bytes;
```
 Encode a 32bit integer into 4 little-endian bytes

## le64
```resynth
resynth fn le64 (
    val: u64,
) -> bytes;
```
 Encode a 64bit integer into 8 little-endian bytes

## len_be16
```resynth
resynth fn len_be16 (
    adjust: u16 = 0x0000,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Prefix a buffer with a 16-bit big-endian length field

 ### Arguments
 * `adjust: u16` An adjustment value to add to the prefixed length

## len_be32
```resynth
resynth fn len_be32 (
    adjust: u32 = 0x00000000,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Prefix a buffer with a 32-bit big-endian length field

 ### Arguments
 * `adjust: u32` An adjustment value to add to the prefixed length

## len_be64
```resynth
resynth fn len_be64 (
    adjust: u64 = 0x0000000000000000,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Prefix a buffer with a 64-bit big-endian length field

 ### Arguments
 * `adjust: u64` An adjustment value to add to the prefixed length

## len_u8
```resynth
resynth fn len_u8 (
    adjust: u8 = 0x00,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Prefix a buffer with a 8-bit byte length field

 ### Arguments
 * `adjust: u8` An adjustment value to add to the prefixed length

## u8
```resynth
resynth fn u8 (
    val: u8,
) -> bytes;
```
 Convert an integer into a one-byte string
