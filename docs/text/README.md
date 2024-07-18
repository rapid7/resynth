 # Text / Byte-String Functions
## Index


### Functions

- [concat](#concat)
- [crlflines](#crlflines)
- [len](#len)

### Constants

| Name | Value |
| ---- | ----- |
| CRLF | `(bytes)"\r\n"` |



## concat
```resynth
resynth fn concat (
    =>
    *collect_args: bytes,
) -> bytes;
```
 Concatenate strings

## crlflines
```resynth
resynth fn crlflines (
    =>
    *collect_args: bytes,
) -> bytes;
```
 join strings with CRLF line-endings

## len
```resynth
resynth fn len (
    =>
    *collect_args: bytes,
) -> u64;
```
 Return the length of a string (or strings)
