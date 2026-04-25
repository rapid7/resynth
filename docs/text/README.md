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

| | Name | Type |
|-| ---- | ---- |
| collect | `*args` | `bytes` |
| returns | | `bytes` |

## crlflines
```resynth
resynth fn crlflines (
    =>
    *collect_args: bytes,
) -> bytes;
```
 join strings with CRLF line-endings

| | Name | Type |
|-| ---- | ---- |
| collect | `*args` | `bytes` |
| returns | | `bytes` |

## len
```resynth
resynth fn len (
    =>
    *collect_args: bytes,
) -> u64;
```
 Return the length of a string (or strings)

| | Name | Type |
|-| ---- | ---- |
| collect | `*args` | `bytes` |
| returns | | `u64` |
