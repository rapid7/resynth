 # Buffered I/O

 A stateful byte buffer that can be read in sequential chunks. Useful for
 splitting a pre-built payload (such as a TLS record or protocol message)
 across multiple packets without duplicating the content.

 Create with `io::bufio(...)`, then call `read(n)` to consume `n` bytes at
 a time, or `read_all()` to consume the remainder.
## Index


### Functions

- [read](#read)
- [read_all](#read_all)



## read
```resynth
resynth fn read (
    bytes: u64,
) -> bytes;
```
 Read the next `bytes` bytes from the buffer, advancing the read position.
 If fewer than `bytes` bytes remain, returns what is left.

## read_all
```resynth
resynth fn read_all (
) -> bytes;
```
 Read all remaining bytes from the buffer, advancing the read position to the end.
