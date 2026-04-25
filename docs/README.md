 # Resynth Standard Library

 Resynth is a packet synthesis language for building precise, readable
 network captures. Programs are compiled to `.pcap` files that can be
 used to test DPI engines, intrusion detection systems, protocol
 decoders, and other network analysis tools.

 A resynth program imports modules from this standard library, constructs
 flows and datagrams using typed functions, and emits packets by
 evaluating expressions. The language is small by design: there are
 exactly three statement forms, one binary operator, and a handful of
 literal types — but the stdlib covers a wide range of protocols.

 See the [language grammar and type system](grammar.md) for a full
 reference on syntax, types, calling conventions, and byte-encoding
 semantics.
## Index


### Modules

| Module | Description |
| ------ | ----------- |
| [arp](arp/README.md) | Address Resolution Protocol |
| [dhcp](dhcp/README.md) | DHCP / BOOTP |
| [dns](dns/README.md) | Domain Name System |
| [erspan1](erspan1/README.md) | ERSPAN Version 1 |
| [erspan2](erspan2/README.md) | ERSPAN Version 2 |
| [erspan3](erspan3/README.md) | ERSPAN Version 3 |
| [eth](eth/README.md) | Ethernet |
| [gre](gre/README.md) | Generic Routing Encapsulation (GRE) |
| [io](io/README.md) | Buffers and File I/O |
| [ipv4](ipv4/README.md) | Internet Protocol Version 4 |
| [netbios](netbios/README.md) | Microsoft NetBIOS |
| [std](std/README.md) | Standard types |
| [text](text/README.md) | Text / Byte-String Functions |
| [time](time/README.md) | Time Manipulation |
| [tls](tls/README.md) | Transport Layer Security (TLS) |
| [vxlan](vxlan/README.md) | VXLAN Encapsulation |
