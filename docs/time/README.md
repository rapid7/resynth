 # Time Manipulation

 Functions to control packet timestamps and introduce time offsets in captures.
## Index


### Functions

| Function | Returns | Description |
| -------- | ------- | ----------- |
| [jump_micros](#jump_micros) | `TimeJump` | Advance the pcap timestamp clock by some number of microseconds |
| [jump_millis](#jump_millis) | `TimeJump` | Advance the pcap timestamp clock by some number of milliseconds |
| [jump_nanos](#jump_nanos) | `TimeJump` | Advance the pcap timestamp clock by some number of nanoseconds |
| [jump_seconds](#jump_seconds) | `TimeJump` | Advance the pcap timestamp clock by some number of seconds |



## jump_micros
```resynth
resynth fn jump_micros (
    us: u64,
) -> TimeJump;
```
Advance the pcap timestamp clock by some number of microseconds

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `us` | `u64` | Number of microseconds to advance the clock |

### Returns

| Type |
| ---- |
| `TimeJump` |

## jump_millis
```resynth
resynth fn jump_millis (
    ms: u64,
) -> TimeJump;
```
Advance the pcap timestamp clock by some number of milliseconds

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `ms` | `u64` | Number of milliseconds to advance the clock |

### Returns

| Type |
| ---- |
| `TimeJump` |

## jump_nanos
```resynth
resynth fn jump_nanos (
    ns: u64,
) -> TimeJump;
```
Advance the pcap timestamp clock by some number of nanoseconds

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `ns` | `u64` | Number of nanoseconds to advance the clock |

### Returns

| Type |
| ---- |
| `TimeJump` |

## jump_seconds
```resynth
resynth fn jump_seconds (
    seconds: u32,
) -> TimeJump;
```
Advance the pcap timestamp clock by some number of seconds

### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| `seconds` | `u32` | Number of seconds to advance the clock |

### Returns

| Type |
| ---- |
| `TimeJump` |
