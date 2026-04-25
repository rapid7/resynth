 # UDP Flow
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [client_dgram](#client_dgram) | `Pkt` | Send a datagram from client to server |
| [client_raw_dgram](#client_raw_dgram) | `bytes` | Return a datagram from client to server (minus IP header) |
| [server_dgram](#server_dgram) | `Pkt` | Send a datagram from server to client |
| [server_raw_dgram](#server_raw_dgram) | `bytes` | Return a datagram from server to client (minus IP header) |



## client_dgram
```resynth
resynth fn client_dgram (
    frag_off: u16 = 0x0000,
    csum: bool = true,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Send a datagram from client to server

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `frag_off` | `u16` | IP fragment offset (in 8-byte units) for the enclosing IP datagram _(default: `0x0000`)_ |
| `csum` | `bool` | If true, compute and fill in the UDP checksum _(default: `true`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |

## client_raw_dgram
```resynth
resynth fn client_raw_dgram (
    csum: bool = true,
    =>
    *collect_args: bytes,
) -> bytes;
```
Return a datagram from client to server (minus IP header)

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `csum` | `bool` | If true, compute and fill in the UDP checksum _(default: `true`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |

## server_dgram
```resynth
resynth fn server_dgram (
    frag_off: u16 = 0x0000,
    csum: bool = true,
    =>
    *collect_args: bytes,
) -> Pkt;
```
Send a datagram from server to client

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `frag_off` | `u16` | IP fragment offset (in 8-byte units) for the enclosing IP datagram _(default: `0x0000`)_ |
| `csum` | `bool` | If true, compute and fill in the UDP checksum _(default: `true`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `Pkt` |

## server_raw_dgram
```resynth
resynth fn server_raw_dgram (
    csum: bool = true,
    =>
    *collect_args: bytes,
) -> bytes;
```
Return a datagram from server to client (minus IP header)

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `csum` | `bool` | If true, compute and fill in the UDP checksum _(default: `true`)_ |
| `…` | `bytes` | Zero or more additional values |

### Returns

| Type |
| ---- |
| `bytes` |
