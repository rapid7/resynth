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
) -> Obj;
```
 Create a buffer from a string, from which you can read parts in sequence

## file
```resynth
resynth fn file (
    filename: bytes,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Load the contents of a file into a string
