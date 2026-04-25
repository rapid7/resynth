# resynth: A Network Packet Synthesis Language

[![Latest Version](https://img.shields.io/crates/v/resynth)](https://crates.io/crates/resynth/)
[![Documentation](https://img.shields.io/docsrs/resynth)](https://docs.rs/resynth/latest/resynth/)

## About

When you build software that processes network traffic — a DPI engine, an IDS,
a protocol parser — you need test data. Real packet captures are hard to work
with: they're noisy, may contain sensitive data, and most importantly they're
opaque binary blobs. Checking pcap files into version control (as tools like
[suricata-verify](https://github.com/OISF/suricata-verify) require) means your
test data is unreadable, un-reviewable, and its history is meaningless.

Resynth is a language for describing exactly what should happen on the wire. You
write human-readable source files that describe network flows, and resynth
compiles them to pcap files. The source files live in version control alongside
the code they test — diffs are readable, reviews are meaningful, and the intent
behind each test case is transparent rather than buried in a binary. When you
need a variant of an existing test (a truncated payload, a different cipher
suite, an extra retransmission), you copy the source file and edit it. With
pcaps, that same change means firing up a packet editor or regenerating the
capture from scratch.

Beyond the version control story, resynth gives you precise control over what
goes on the wire. You can craft fragmented IP datagrams, reordered TCP segments,
truncated protocol headers, or any other edge case that's difficult or
impossible to capture from real traffic. Higher-level protocol modules handle
the tedious byte-layout work so you can focus on describing the scenario.


## Example

A minimal UDP exchange:

```
import ipv4;

let flow = ipv4::udp::flow(
  192.168.0.1/12345,
  8.8.8.8/53,
);

flow.client_dgram("hello");
flow.server_dgram("world");
```

Run `resynth hello.rsyn` and a `hello.pcap` file will be created.

Here is a more complete example representing a DNS lookup followed by an HTTP
request and response:

```
import ipv4;
import dns;
import text;

let cl = 192.168.0.1;
let sv = 109.197.38.8;

dns::host(cl, "www.scaramanga.co.uk", ns: 8.8.8.8, sv);

let http = ipv4::tcp::flow(
  cl/32768,
  sv/80,
);

http.open();

http.client_message(
  text::crlflines(
    "GET / HTTP/1.1",
    "Host: www.scaramanga.co.uk",
    text::CRLF,
  )
);

http.server_message(
  text::crlflines(
    "HTTP/1.1 301 Moved Permanently",
    "Date: Sat, 17 Jul 2021 02:55:05 GMT",
    "Server: Apache/2.4.29 (Ubuntu)",
    "Location: https://www.scaramanga.co.uk/",
    "Content-Type: text/html; charset=iso-8859-1",
    text::CRLF,
  ),
);

http.server_close();
```


## Currently Supported Protocols

At the lowest level you have full control: arbitrary TCP, UDP, and ICMP
packets, raw IP datagrams, IP fragments, and reordered or retransmitted
segments. Higher-level library modules are available for:

- DNS
- DHCP
- TLS (including crafting arbitrary record sequences and malformed frames)
- NetBIOS name service (NBNS)
- VXLAN, GRE, ERSPAN Types I, II & III
- Ethernet
- I/O: embed the contents of an external file (e.g. a certificate) into a packet


## Design Goals

**Packets as code.** Source files are plain text. They can be read, reviewed,
and diffed like any other code. The intent behind a test case is visible without
opening a packet analyser. And because they're just text, test cases can be
copied and modified — varying one field, adding a fragment, changing a cipher
suite — in a way that's simply not possible with an opaque binary pcap.

**Precise control.** Fragmented reassembly, out-of-order delivery, truncated
headers, crafted TLS handshakes — things that are difficult to capture from real
traffic and tedious to construct by hand are straightforward to describe.

**High-level where helpful, low-level where necessary.** Protocol modules handle
checksums, sequence numbers, and framing automatically. When you need to go
off-script, raw bytes can be injected anywhere using inline hex escapes:
`"some payload|0d 0a|more payload"`.

**Speed.** The compiler is written in Rust. Generating thousands of test pcaps
is fast enough that it can be a routine part of a build or test pipeline.


## Why not use $OTHER\_TOOL?

- **Scapy and other Python frameworks**: too slow for high-rate generation or
  fuzz-testing workloads, and the programs don't lend themselves to
  the compile-to-artifact workflow that makes test data versionable.
- **flowsynth**: a big source of inspiration, but limited to lower-level
  primitives with no support for higher-level protocol construction or
  extensibility.
- **Checking in pcap files directly**: the standard approach for tools like
  suricata-verify, but pcaps are binary, opaque to code review, and wasteful
  in version control history.


## Future Directions

I plan to combine this with a DPDK-based packet generator in order to build a
network performance-testing suite (think T-Rex). The idea would be to add a
multi-instancing feature to the language to scale up the number of flows. The
resynth programs would be compiled in to a set of pre-canned packet templates
which could just be copied in to the tx ring-buffer with fields (eg. IP
addresses and port numbers) modulated. This would move all of the expensive
work out of the packet transmit mainloop and allow us to generate traffic at
upwards of 20Gbps per CPU.

I plan to add support for the following protocols to the standard library:
- Support for PMTU and segmentation of TCP messages
- More direct support for HTTP
- ARP
- SMB2
- DCE-RPC
- More exotic TCP/IP interactions and better ICMP support
