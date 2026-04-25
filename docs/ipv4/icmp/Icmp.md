 # ICMP Session
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [echo](#echo) | `Pkt` | ICMP Ping |
| [echo_reply](#echo_reply) | `Pkt` | ICMP Ping reply |



## echo
```resynth
resynth fn echo (
    payload: bytes,
) -> Pkt;
```
ICMP Ping

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `payload` | `bytes` | Payload bytes for the ICMP echo request |

### Returns

| Type |
| ---- |
| `Pkt` |

## echo_reply
```resynth
resynth fn echo_reply (
    payload: bytes,
) -> Pkt;
```
ICMP Ping reply

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `payload` | `bytes` | Payload bytes for the ICMP echo reply |

### Returns

| Type |
| ---- |
| `Pkt` |
