 # Microsoft NetBIOS

 NetBIOS over TCP/IP — name encoding, name-service queries, and protocol constants.

 ## Wire format

 NetBIOS Name Service (NBNS, UDP port 137) uses the DNS wire format: the same
 12-byte header, question, and resource record structures. Use the `dns` module
 helpers (`dns::hdr`, `dns::flags`, `dns::name`, `dns::answer`) to build the
 packet framing, and the `netbios` helpers for name encoding and NBNS-specific
 constants.

 ### Example: positive Name Query Response for "BILLG" (workstation)

 ```resynth
 import ipv4;
 import dns;
 import netbios;

 ipv4::udp::unicast(
     192.168.1.100/137,
     192.168.1.1/137,
     dns::hdr(
         0x1234,
         netbios::ns::flags(netbios::ns::opcode::QUERY, response: true, aa: true, ra: true),
         ancount: 1,
     ),
     dns::answer(
         dns::name(netbios::name::encode("BILLG")),
         atype: netbios::ns::rrtype::NB,
         ttl: 300,
         std::be16(0x0000),       # NB_FLAGS: B-node, unique
         192.168.1.100,           # NB_ADDRESS
     ),
 );
 ```
## Index


### Modules

| Module | Description |
| ------ | ----------- |
| [name](name/README.md) | NetBIOS names |
| [ns](ns/README.md) | NetBIOS Name Service |
