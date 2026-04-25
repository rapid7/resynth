 # ICMP Session
## Index


### Functions

- [echo](#echo)
- [echo_reply](#echo_reply)



## echo
```resynth
resynth fn echo (
    payload: bytes,
) -> Pkt;
```
 ICMP Ping

| | Name | Type |
|-| ---- | ---- |
| arg | `payload` | `bytes` |
| returns | | `Pkt` |

## echo_reply
```resynth
resynth fn echo_reply (
    payload: bytes,
) -> Pkt;
```
 ICMP Ping reply

| | Name | Type |
|-| ---- | ---- |
| arg | `payload` | `bytes` |
| returns | | `Pkt` |
