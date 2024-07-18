 # Transport Layer Security (TLS)

 ## Example
 ```resynth
 import io;
 import ipv4;
 import std;
 import tls;

 let tls = ipv4::tcp::flow(
   192.168.106.72:40015,
   172.16.14.121:443,
 );

 tls.open();

 // Client Hello
 tls.client_message(
   tls::message(
     content: tls::content::HANDSHAKE,
     version: tls::version::TLS_1_0,
     tls::client_hello(
       ciphers: tls::ciphers(
         tls::cipher::ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
         tls::cipher::ECDHE_RSA_WITH_AES_256_GCM_SHA384,
         tls::cipher::ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
         tls::cipher::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
         tls::cipher::ECDHE_ECDSA_WITH_AES_256_CCM,
         tls::cipher::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
         tls::cipher::ECDHE_RSA_WITH_AES_128_GCM_SHA256,
         tls::cipher::ECDHE_ECDSA_WITH_AES_128_CCM,
         tls::cipher::ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
         tls::cipher::ECDHE_RSA_WITH_AES_128_CBC_SHA256,
         tls::cipher::ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
         tls::cipher::ECDHE_RSA_WITH_AES_256_CBC_SHA,
         tls::cipher::ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
         tls::cipher::ECDHE_RSA_WITH_AES_128_CBC_SHA,
         tls::cipher::RSA_WITH_AES_256_GCM_SHA384,
         tls::cipher::RSA_WITH_AES_256_CCM,
         tls::cipher::RSA_WITH_AES_128_GCM_SHA256,
         tls::cipher::RSA_WITH_AES_128_CCM,
         tls::cipher::RSA_WITH_AES_256_CBC_SHA256,
         tls::cipher::RSA_WITH_AES_128_CBC_SHA256,
         tls::cipher::RSA_WITH_AES_256_CBC_SHA,
         tls::cipher::RSA_WITH_AES_128_CBC_SHA,
         tls::cipher::DHE_RSA_WITH_AES_256_GCM_SHA384,
         tls::cipher::DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
         tls::cipher::DHE_RSA_WITH_AES_256_CCM,
         tls::cipher::DHE_RSA_WITH_AES_128_GCM_SHA256,
         tls::cipher::DHE_RSA_WITH_AES_128_CCM,
         tls::cipher::DHE_RSA_WITH_AES_256_CBC_SHA256,
         tls::cipher::DHE_RSA_WITH_AES_128_CBC_SHA256,
         tls::cipher::DHE_RSA_WITH_AES_256_CBC_SHA,
         tls::cipher::DHE_RSA_WITH_AES_128_CBC_SHA,
         tls::cipher::EMPTY_RENEGOTIATION_INFO_SCSV,
       ),
       version: tls::version::TLS_1_2,

       tls::sni("test.local"),

       tls::extension(
         tls::ext::EC_POINT_FORMATS,
         std::len_u8(
           "|00 01 02|",
         )
       ),

       tls::extension(
         tls::ext::SUPPORTED_GROUPS,
         std::len_be16(
           "|00 1d 00 17 00 1e 00 19 00 18|",
         ),
       ),

       tls::extension(
         tls::ext::SESSION_TICKET,
       ),

       tls::extension(
         tls::ext::ENCRYPT_THEN_MAC,
       ),

       tls::extension(
         tls::ext::EXTENDED_MASTER_SECRET,
       ),

       tls::extension(
         tls::ext::SIGNATURE_ALGORITHMS,
         std::len_be16(
           "|04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b|",
           "|08 04 08 05 08 06 04 01 05 01 06 01 03 03 03 01|",
         ),
       ),

       tls::extension(
         tls::ext::ALPN,
         std::len_be16(
           std::len_u8("postgresql"),
           std::len_u8("http/0.9"),
           std::len_u8("imap"),
           std::len_u8("pop3"),
           std::len_u8("h2"),
         ),
       ),
     )
   ),
 );

 tls.server_message(
   tls::message(
     content: tls::content::HANDSHAKE,
     version: tls::version::TLS_1_2,
     tls::server_hello(
       version: tls::version::TLS_1_2,
       cipher: tls::cipher::ECDHE_RSA_WITH_AES_256_GCM_SHA384,
       tls::extension(
         tls::ext::RENEGOTIATION_INFO,
         std::u8(0),
       ),
       tls::extension(
         tls::ext::EC_POINT_FORMATS,
         std::len_u8(
           std::u8(0),
           std::u8(1),
           std::u8(2),
         ),
       ),
       tls::extension(
         tls::ext::SESSION_TICKET,
       ),
       tls::extension(
         tls::ext::EXTENDED_MASTER_SECRET,
       ),
       tls::extension(
         tls::ext::ALPN,
         std::len_be16(
           std::len_u8("http/0.9"),
           std::len_u8("pop3"),
         ),
       ),
     ),
   ),


   tls::message(
     content: tls::content::HANDSHAKE,
     version: tls::version::TLS_1_2,
     tls::certificates(
       io::file("./example-data/rsa4096.x509.cert.der"),
     )
   ),

   // Server Key Exchange
   tls::message(
     content: tls::content::HANDSHAKE,
     version: tls::version::TLS_1_2,
     tls::handshake::SERVER_KEY_EXCHANGE,
     "|00 02 28 03 00 1d 20 2f b5 e1 12 ca 8a de fc 9b c9 96 ed eb 63 8e df e5|",
     "|aa 96 57 cd 0f 39 7c 46 b0 18 49 b3 48 3c 70 08 04 02 00 42 27 29 90 25|",
     "|ef a9 ab 29 b2 ec d2 24 6b f7 9a cc 1e 2a 49 44 93 fb b6 0a 75 51 40 40|",
     "|90 45 d2 fb d2 c7 0a be 68 5b 90 45 c2 00 19 29 b5 6f 70 0c cb b6 c6 15|",
     "|fb 1c 4a fe 48 10 d2 d0 de a3 1d 54 7f 8f 5f 93 5c 71 68 77 6b 60 62 d2|",
     "|6c 4c 8f 05 00 61 f1 18 0e 6a e8 18 99 3e 44 b6 b9 52 d0 cb 70 dd ad 50|",
     "|01 af 07 98 a3 7b 13 4c c8 21 cb f5 54 14 d3 b3 ee 76 5b ce cb f7 ac a6|",
     "|49 f9 6f 2b ec e0 5b 3e 4c f3 22 88 f9 00 1c 5d 20 91 31 64 ed 85 48 03|",
     "|c7 8b 41 14 4d 04 5d 68 92 ca 21 09 c0 2d bc dd 00 74 26 7d 85 45 6a 44|",
     "|c9 82 36 19 b3 d3 3b 34 10 7f b9 7c e1 23 a1 1b 35 5f 1f 73 57 3d 9b c2|",
     "|d2 20 92 ac 22 cb ac 82 15 1a 7c 64 ae 93 c0 e0 03 c1 87 9c c5 ff c2 3d|",
     "|1b d7 d6 22 44 eb c2 a5 81 b0 11 71 c0 ac 47 3d 6e 2c b3 61 7d d0 13 df|",
     "|4f a5 5b bd 60 c0 cf 94 3c de de 19 c3 07 04 55 b7 c2 3a ca 90 33 0c 9f|",
     "|e5 ee b5 35 37 f9 b8 9c 0c 9e 8c 1e f2 15 56 05 fc af 77 a1 81 6c 7a c8|",
     "|27 fa ac 54 aa 2e 19 75 fe 71 2b bf f6 be 16 6d c3 46 09 97 65 36 b5 45|",
     "|45 37 eb 5b b9 b2 f9 58 d4 50 45 d7 86 ae 45 8f 57 54 79 b8 14 1c 70 26|",
     "|45 18 01 47 d6 9b e2 a8 0c 50 73 15 9a 52 c6 c1 15 ce 61 33 1f 6e a6 99|",
     "|38 39 29 31 29 eb da 82 5e 86 cc 4a f1 9c d2 ad 26 7d ac ed 54 0f e2 07|",
     "|32 05 22 9a bf 57 b2 7d 53 e8 7f ce 9c 0c ed b6 02 2c ab 6a 2d 14 20 96|",
     "|ca de eb 55 d4 17 83 30 c2 da df 7c 59 f9 7c 08 c2 14 37 0a 30 b5 94 13|",
     "|34 c2 a5 12 1d 11 c4 77 40 e4 d9 a1 5e b4 7e 2a a9 14 06 c1 57 2e 02 f3|",
     "|7d 05 9e 07 70 a7 2b fc 41 a4 db 7e ae 7b 34 1f cd 05 43 ed 15 06 72 6d|",
     "|f2 82 1c 9d 94 a3 87 97 7f 09 7b 38 c3 8b 10 93 e5 0a 11 1e 24 0f e7 0a|",
     "|ce e8 35|"
   ),

   // Server Hello Done
   tls::message(
     content: tls::content::HANDSHAKE,
     version: tls::version::TLS_1_2,
     tls::handshake::SERVER_HELLO_DONE,
     "|00 00 00|"
   ),
 );
 ```
## Index


### Modules

- [cipher](cipher/README.md)
- [content](content/README.md)
- [ext](ext/README.md)
- [handshake](handshake/README.md)
- [version](version/README.md)

### Functions

- [certificates](#certificates)
- [ciphers](#ciphers)
- [client_hello](#client_hello)
- [extension](#extension)
- [message](#message)
- [server_hello](#server_hello)
- [sni](#sni)



## certificates
```resynth
resynth fn certificates (
    =>
    *collect_args: bytes,
) -> bytes;
```
 Returns a chain of X.509 certificates

## ciphers
```resynth
resynth fn ciphers (
    =>
    *collect_args: u16,
) -> bytes;
```
 Returns a TLS ciphers list

 ### Arguments
 * `*cipher: u16` the [TLS ciphers](cipher/README.md)

## client_hello
```resynth
resynth fn client_hello (
    version: u16 = 0x0303,
    sessionid: bytes = "\x00",
    ciphers: bytes = "\x00\x02\x00\x00",
    compression: bytes = "\x01\x00",
    =>
    *collect_args: bytes,
) -> bytes;
```
 Returns a TLS client hello

 This has to be framed inside a content::HANDSHAKE [message](#message)

 ### Arguments
 * `version: u16` Requested [TLS version](version/README.md)
 * `sessionid: Str` Session ID, should be a u8 len prefixed buffer
 * `ciphers: Str` Supported [ciphers](cipher/README.md) eg. as created with
                  [ciphers()][#ciphers]
 * `compression: Str` Supported compression algorithms (pretty much defunct)
 * `*extensions: Str` Extensions, eg. as created by [extension()](#extension)

## extension
```resynth
resynth fn extension (
    ext: u16,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Returns a TLS extension

 This implements the TLS extension framing:

 ```c
 struct tls_ext {
     uint16_t ext;
     uint16_t len;
     uint8_t payload[0];
 } _packed;
 ```

 ### Arguments
 * `ext: u16` [TLS Extension](ext/README.md)
 * `*payload: Str` the payload bytes

## message
```resynth
resynth fn message (
    version: u16 = 0x0303,
    content: u8 = 0x16,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Returns a TLS record

 This implements the TLS record framing:

 ```c
 struct tls_hdr {
     uint8_t content;
     uint16_t version;
     uint16_t len;
     uint8_t payload[0];
 } _packed;
 ```

 ### Arguments
 * `version: u16` [TLS version](version/README.md)
 * `content: u8` The [TLS message type](content/README.md)
 * `*payload: Str` the payload bytes

## server_hello
```resynth
resynth fn server_hello (
    version: u16 = 0x0303,
    sessionid: bytes = "\x00",
    cipher: u16 = 0x0000,
    compression: u8 = 0x00,
    =>
    *collect_args: bytes,
) -> bytes;
```
 Returns a TLS server hello

 This has to be framed inside a content::HANDSHAKE [message](#message)

 ### Arguments
 * `version: u16` Negotiated [TLS version](version/README.md)
 * `sessionid: Str` Session ID, should be a u8 len prefixed buffer
 * `cipher: u16` Negotiated [ciphers](cipher/README.md)
 * `compression: u8` Negotiated compression algorithm (pretty much defunct)
 * `*extensions: Str` Extensions, eg. as created by [extension()](#extension)

## sni
```resynth
resynth fn sni (
    =>
    *collect_args: bytes,
) -> bytes;
```
 Returns a TLS SNI extension

 The SNI extension is the Server Name Indictator

 ### Arguments
 * `name: Str` Server Names
