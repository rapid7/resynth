 # Time Manipulation
## Index


### Functions

- [jump_micros](#jump_micros)
- [jump_millis](#jump_millis)
- [jump_nanos](#jump_nanos)
- [jump_seconds](#jump_seconds)



## jump_micros
```resynth
resynth fn jump_micros (
    us: u64,
) -> TimeJump;
```
 Advance the pcap timestamp clock by some number of microseconds

## jump_millis
```resynth
resynth fn jump_millis (
    ms: u64,
) -> TimeJump;
```
 Advance the pcap timestamp clock by some number of milliseconds

## jump_nanos
```resynth
resynth fn jump_nanos (
    ns: u64,
) -> TimeJump;
```
 Advance the pcap timestamp clock by some number of nanoseconds

## jump_seconds
```resynth
resynth fn jump_seconds (
    seconds: u32,
) -> TimeJump;
```
 Advance the pcap timestamp clock by some number of seconds
