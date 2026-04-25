 # Buffers and File I/O
## Index


### Classes

- [BufIO](BufIO.md)

### Functions

- [bufio](#bufio)
- [file](#file)



## bufio
```resynth
resynth fn bufio (
    =>
    *collect_args: bytes,
) -> BufIO;
```
 Create a `BufIO` buffer from one or more byte strings, from which bytes
 can be consumed in sequential chunks using `read(n)` and `read_all()`.
 This is useful for splitting a pre-assembled payload across multiple
 packets — for example, sending the first 15 bytes of a TLS record in one
 TCP segment and the rest in another.

| | Name | Type |
|-| ---- | ---- |
| collect | `*args` | `bytes` |
| returns | | [BufIO](../io/BufIO.md) |

## file
```resynth
resynth fn file (
    filename: bytes,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Load the contents of a file into a string

| | Name | Type |
|-| ---- | ---- |
| arg | `filename` | `bytes` |
| collect | `*args` | `bytes` |
| returns | | `bytes` |
