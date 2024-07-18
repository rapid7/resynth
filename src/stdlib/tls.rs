use pkt::tls::{ciphers, content, ext, handshake, version};

use crate::libapi::{FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use crate::{func, module};

const VERSION: Module = module!(
    /// # TLS Versions
    resynth mod version {
        SSL_1 => Symbol::u16(version::SSL_1),
        SSL_2 => Symbol::u16(version::SSL_2),
        SSL_3 => Symbol::u16(version::SSL_3),
        TLS_1_0 => Symbol::u16(version::TLS_1_0),
        TLS_1_1 => Symbol::u16(version::TLS_1_1),
        TLS_1_2 => Symbol::u16(version::TLS_1_2),
        TLS_1_3 => Symbol::u16(version::TLS_1_3),
    }
);

const CONTENT: Module = module! {
    /// # TLS Record Content Types
    resynth mod content {
        INVALID => Symbol::u8(content::INVALID),
        CHANGE_CIPHER_SPEC => Symbol::u8(content::CHANGE_CIPHER_SPEC),
        ALERT => Symbol::u8(content::ALERT),
        HANDSHAKE => Symbol::u8(content::HANDSHAKE),
        APP_DATA => Symbol::u8(content::APP_DATA),
        HEARTBEAT => Symbol::u8(content::HEARTBEAT),
        TLS12_CID => Symbol::u8(content::TLS12_CID),
        ACK => Symbol::u8(content::ACK),
    }
};

const HANDSHAKE: Module = module! {
    /// # TLS Handshake types
    resynth mod handshake {
        HELLO_REQUEST => Symbol::u8(handshake::HELLO_REQUEST),
        CLIENT_HELLO => Symbol::u8(handshake::CLIENT_HELLO),
        SERVER_HELLO => Symbol::u8(handshake::SERVER_HELLO),
        HELLO_VERIFY_REQUEST => Symbol::u8(handshake::HELLO_VERIFY_REQUEST),
        NEW_SESSION_TICKET => Symbol::u8(handshake::NEW_SESSION_TICKET),
        END_OF_EARLY_DATA => Symbol::u8(handshake::END_OF_EARLY_DATA),
        HELLO_RETRY_REQUEST => Symbol::u8(handshake::HELLO_RETRY_REQUEST),
        ENCRYPTED_EXTENSIONS => Symbol::u8(handshake::ENCRYPTED_EXTENSIONS),
        REQUESTCONNECTIONID => Symbol::u8(handshake::REQUESTCONNECTIONID),
        NEWCONNECTIONID => Symbol::u8(handshake::NEWCONNECTIONID),
        CERTIFICATE => Symbol::u8(handshake::CERTIFICATE),
        SERVER_KEY_EXCHANGE => Symbol::u8(handshake::SERVER_KEY_EXCHANGE),
        CERTIFICATE_REQUEST => Symbol::u8(handshake::CERTIFICATE_REQUEST),
        SERVER_HELLO_DONE => Symbol::u8(handshake::SERVER_HELLO_DONE),
        CERTIFICATE_VERIFY => Symbol::u8(handshake::CERTIFICATE_VERIFY),
        CLIENT_KEY_EXCHANGE => Symbol::u8(handshake::CLIENT_KEY_EXCHANGE),
        FINISHED => Symbol::u8(handshake::FINISHED),
        CERTIFICATE_URL => Symbol::u8(handshake::CERTIFICATE_URL),
        CERTIFICATE_STATUS => Symbol::u8(handshake::CERTIFICATE_STATUS),
        SUPPLEMENTAL_DATA => Symbol::u8(handshake::SUPPLEMENTAL_DATA),
        KEY_UPDATE => Symbol::u8(handshake::KEY_UPDATE),
        COMPRESSED_CERTIFICATE => Symbol::u8(handshake::COMPRESSED_CERTIFICATE),
        EKT_KEY => Symbol::u8(handshake::EKT_KEY),
        MESSAGE_HASH => Symbol::u8(handshake::MESSAGE_HASH),
    }
};

const EXT: Module = module! {
    /// # TLS Extensions
    resynth mod ext {
        SERVER_NAME => Symbol::u16(ext::SERVER_NAME),
        MAX_FRAGMENT_LENGTH => Symbol::u16(ext::MAX_FRAGMENT_LENGTH),
        CLIENT_CERTIFICATE_URL => Symbol::u16(ext::CLIENT_CERTIFICATE_URL),
        TRUSTED_CA_KEYS => Symbol::u16(ext::TRUSTED_CA_KEYS),
        TRUNCATED_HMAC => Symbol::u16(ext::TRUNCATED_HMAC),
        STATUS_REQUEST => Symbol::u16(ext::STATUS_REQUEST),
        USER_MAPPING => Symbol::u16(ext::USER_MAPPING),
        CLIENT_AUTHZ => Symbol::u16(ext::CLIENT_AUTHZ),
        SERVER_AUTHZ => Symbol::u16(ext::SERVER_AUTHZ),
        CERT_TYPE => Symbol::u16(ext::CERT_TYPE),
        SUPPORTED_GROUPS => Symbol::u16(ext::SUPPORTED_GROUPS),
        EC_POINT_FORMATS => Symbol::u16(ext::EC_POINT_FORMATS),
        SRP => Symbol::u16(ext::SRP),
        SIGNATURE_ALGORITHMS => Symbol::u16(ext::SIGNATURE_ALGORITHMS),
        USE_SRTP => Symbol::u16(ext::USE_SRTP),
        HEARTBEAT => Symbol::u16(ext::HEARTBEAT),
        APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            => Symbol::u16(ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        ALPN
            => Symbol::u16(ext::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        STATUS_REQUEST_V2 => Symbol::u16(ext::STATUS_REQUEST_V2),
        SIGNED_CERTIFICATE_TIMESTAMP => Symbol::u16(ext::SIGNED_CERTIFICATE_TIMESTAMP),
        CLIENT_CERTIFICATE_TYPE => Symbol::u16(ext::CLIENT_CERTIFICATE_TYPE),
        SERVER_CERTIFICATE_TYPE => Symbol::u16(ext::SERVER_CERTIFICATE_TYPE),
        PADDING => Symbol::u16(ext::PADDING),
        ENCRYPT_THEN_MAC => Symbol::u16(ext::ENCRYPT_THEN_MAC),
        EXTENDED_MASTER_SECRET => Symbol::u16(ext::EXTENDED_MASTER_SECRET),
        TOKEN_BINDING => Symbol::u16(ext::TOKEN_BINDING),
        CACHED_INFO => Symbol::u16(ext::CACHED_INFO),
        TLS_LTS => Symbol::u16(ext::TLS_LTS),
        COMPRESS_CERTIFICATE => Symbol::u16(ext::COMPRESS_CERTIFICATE),
        RECORD_SIZE_LIMIT => Symbol::u16(ext::RECORD_SIZE_LIMIT),
        PWD_PROTECT => Symbol::u16(ext::PWD_PROTECT),
        PWD_CLEAR => Symbol::u16(ext::PWD_CLEAR),
        PASSWORD_SALT => Symbol::u16(ext::PASSWORD_SALT),
        TICKET_PINNING => Symbol::u16(ext::TICKET_PINNING),
        TLS_CERT_WITH_EXTERN_PSK => Symbol::u16(ext::TLS_CERT_WITH_EXTERN_PSK),
        DELEGATED_CREDENTIALS => Symbol::u16(ext::DELEGATED_CREDENTIALS),
        SESSION_TICKET => Symbol::u16(ext::SESSION_TICKET),
        TLMSP => Symbol::u16(ext::TLMSP),
        TLMSP_PROXYING => Symbol::u16(ext::TLMSP_PROXYING),
        TLMSP_DELEGATE => Symbol::u16(ext::TLMSP_DELEGATE),
        SUPPORTED_EKT_CIPHERS => Symbol::u16(ext::SUPPORTED_EKT_CIPHERS),
        PRE_SHARED_KEY => Symbol::u16(ext::PRE_SHARED_KEY),
        EARLY_DATA => Symbol::u16(ext::EARLY_DATA),
        SUPPORTED_VERSIONS => Symbol::u16(ext::SUPPORTED_VERSIONS),
        COOKIE => Symbol::u16(ext::COOKIE),
        PSK_KEY_EXCHANGE_MODES => Symbol::u16(ext::PSK_KEY_EXCHANGE_MODES),
        CERTIFICATE_AUTHORITIES => Symbol::u16(ext::CERTIFICATE_AUTHORITIES),
        OID_FILTERS => Symbol::u16(ext::OID_FILTERS),
        POST_HANDSHAKE_AUTH => Symbol::u16(ext::POST_HANDSHAKE_AUTH),
        SIGNATURE_ALGORITHMS_CERT => Symbol::u16(ext::SIGNATURE_ALGORITHMS_CERT),
        KEY_SHARE => Symbol::u16(ext::KEY_SHARE),
        TRANSPARENCY_INFO => Symbol::u16(ext::TRANSPARENCY_INFO),
        CONNECTION_ID_DEPRECATED => Symbol::u16(ext::CONNECTION_ID_DEPRECATED),
        CONNECTION_ID => Symbol::u16(ext::CONNECTION_ID),
        EXTERNAL_ID_HASH => Symbol::u16(ext::EXTERNAL_ID_HASH),
        EXTERNAL_SESSION_ID => Symbol::u16(ext::EXTERNAL_SESSION_ID),
        QUIC_TRANSPORT_PARAMETERS => Symbol::u16(ext::QUIC_TRANSPORT_PARAMETERS),
        TICKET_REQUEST => Symbol::u16(ext::TICKET_REQUEST),
        DNSSEC_CHAIN => Symbol::u16(ext::DNSSEC_CHAIN),
        RENEGOTIATION_INFO => Symbol::u16(ext::RENEGOTIATION_INFO),
    }
};

const CIPHER: Module = module! {
    /// # TLS Cipher Suites
    resynth mod cipher {
        NULL_WITH_NULL_NULL =>
            Symbol::u16(ciphers::NULL_WITH_NULL_NULL),
        RSA_WITH_NULL_MD5 =>
            Symbol::u16(ciphers::RSA_WITH_NULL_MD5),
        RSA_WITH_NULL_SHA =>
            Symbol::u16(ciphers::RSA_WITH_NULL_SHA),
        RSA_EXPORT_WITH_RC4_40_MD5 =>
            Symbol::u16(ciphers::RSA_EXPORT_WITH_RC4_40_MD5),
        RSA_WITH_RC4_128_MD5 =>
            Symbol::u16(ciphers::RSA_WITH_RC4_128_MD5),
        RSA_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::RSA_WITH_RC4_128_SHA),
        RSA_EXPORT_WITH_RC2_CBC_40_MD5 =>
            Symbol::u16(ciphers::RSA_EXPORT_WITH_RC2_CBC_40_MD5),
        RSA_WITH_IDEA_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_IDEA_CBC_SHA),
        RSA_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::RSA_EXPORT_WITH_DES40_CBC_SHA),
        RSA_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_DES_CBC_SHA),
        RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_3DES_EDE_CBC_SHA),
        DH_DSS_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_EXPORT_WITH_DES40_CBC_SHA),
        DH_DSS_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_DES_CBC_SHA),
        DH_DSS_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_3DES_EDE_CBC_SHA),
        DH_RSA_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_EXPORT_WITH_DES40_CBC_SHA),
        DH_RSA_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_DES_CBC_SHA),
        DH_RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_3DES_EDE_CBC_SHA),
        DHE_DSS_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_EXPORT_WITH_DES40_CBC_SHA),
        DHE_DSS_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_DES_CBC_SHA),
        DHE_DSS_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_3DES_EDE_CBC_SHA),
        DHE_RSA_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_EXPORT_WITH_DES40_CBC_SHA),
        DHE_RSA_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_DES_CBC_SHA),
        DHE_RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_3DES_EDE_CBC_SHA),
        DH_ANON_EXPORT_WITH_RC4_40_MD5 =>
            Symbol::u16(ciphers::DH_ANON_EXPORT_WITH_RC4_40_MD5),
        DH_ANON_WITH_RC4_128_MD5 =>
            Symbol::u16(ciphers::DH_ANON_WITH_RC4_128_MD5),
        DH_ANON_EXPORT_WITH_DES40_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_EXPORT_WITH_DES40_CBC_SHA),
        DH_ANON_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_DES_CBC_SHA),
        DH_ANON_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_3DES_EDE_CBC_SHA),
        KRB5_WITH_DES_CBC_SHA =>
            Symbol::u16(ciphers::KRB5_WITH_DES_CBC_SHA),
        KRB5_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::KRB5_WITH_3DES_EDE_CBC_SHA),
        KRB5_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::KRB5_WITH_RC4_128_SHA),
        KRB5_WITH_IDEA_CBC_SHA =>
            Symbol::u16(ciphers::KRB5_WITH_IDEA_CBC_SHA),
        KRB5_WITH_DES_CBC_MD5 =>
            Symbol::u16(ciphers::KRB5_WITH_DES_CBC_MD5),
        KRB5_WITH_3DES_EDE_CBC_MD5 =>
            Symbol::u16(ciphers::KRB5_WITH_3DES_EDE_CBC_MD5),
        KRB5_WITH_RC4_128_MD5 =>
            Symbol::u16(ciphers::KRB5_WITH_RC4_128_MD5),
        KRB5_WITH_IDEA_CBC_MD5 =>
            Symbol::u16(ciphers::KRB5_WITH_IDEA_CBC_MD5),
        KRB5_EXPORT_WITH_DES_CBC_40_SHA =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_DES_CBC_40_SHA),
        KRB5_EXPORT_WITH_RC2_CBC_40_SHA =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_RC2_CBC_40_SHA),
        KRB5_EXPORT_WITH_RC4_40_SHA =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_RC4_40_SHA),
        KRB5_EXPORT_WITH_DES_CBC_40_MD5 =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_DES_CBC_40_MD5),
        KRB5_EXPORT_WITH_RC2_CBC_40_MD5 =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_RC2_CBC_40_MD5),
        KRB5_EXPORT_WITH_RC4_40_MD5 =>
            Symbol::u16(ciphers::KRB5_EXPORT_WITH_RC4_40_MD5),
        PSK_WITH_NULL_SHA =>
            Symbol::u16(ciphers::PSK_WITH_NULL_SHA),
        DHE_PSK_WITH_NULL_SHA =>
            Symbol::u16(ciphers::DHE_PSK_WITH_NULL_SHA),
        RSA_PSK_WITH_NULL_SHA =>
            Symbol::u16(ciphers::RSA_PSK_WITH_NULL_SHA),
        RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_AES_128_CBC_SHA),
        DH_DSS_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_128_CBC_SHA),
        DH_RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_128_CBC_SHA),
        DHE_DSS_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_128_CBC_SHA),
        DHE_RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_128_CBC_SHA),
        DH_ANON_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_128_CBC_SHA),
        RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_AES_256_CBC_SHA),
        DH_DSS_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_256_CBC_SHA),
        DH_RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_256_CBC_SHA),
        DHE_DSS_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_256_CBC_SHA),
        DHE_RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_256_CBC_SHA),
        DH_ANON_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_256_CBC_SHA),
        RSA_WITH_NULL_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_NULL_SHA256),
        RSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_AES_128_CBC_SHA256),
        RSA_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_AES_256_CBC_SHA256),
        DH_DSS_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_128_CBC_SHA256),
        DH_RSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_128_CBC_SHA256),
        DHE_DSS_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_128_CBC_SHA256),
        RSA_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_128_CBC_SHA),
        DH_DSS_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_128_CBC_SHA),
        DH_RSA_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_128_CBC_SHA),
        DHE_DSS_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_128_CBC_SHA),
        DHE_RSA_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_128_CBC_SHA),
        DH_ANON_WITH_CAMELLIA_128_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_128_CBC_SHA),
        DHE_RSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_128_CBC_SHA256),
        DH_DSS_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_256_CBC_SHA256),
        DH_RSA_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_256_CBC_SHA256),
        DHE_DSS_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_256_CBC_SHA256),
        DHE_RSA_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_256_CBC_SHA256),
        DH_ANON_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_128_CBC_SHA256),
        DH_ANON_WITH_AES_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_256_CBC_SHA256),
        RSA_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_256_CBC_SHA),
        DH_DSS_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_256_CBC_SHA),
        DH_RSA_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_256_CBC_SHA),
        DHE_DSS_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_256_CBC_SHA),
        DHE_RSA_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_256_CBC_SHA),
        DH_ANON_WITH_CAMELLIA_256_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_256_CBC_SHA),
        PSK_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::PSK_WITH_RC4_128_SHA),
        PSK_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::PSK_WITH_3DES_EDE_CBC_SHA),
        PSK_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::PSK_WITH_AES_128_CBC_SHA),
        PSK_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::PSK_WITH_AES_256_CBC_SHA),
        DHE_PSK_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::DHE_PSK_WITH_RC4_128_SHA),
        DHE_PSK_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::DHE_PSK_WITH_3DES_EDE_CBC_SHA),
        DHE_PSK_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_128_CBC_SHA),
        DHE_PSK_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_256_CBC_SHA),
        RSA_PSK_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::RSA_PSK_WITH_RC4_128_SHA),
        RSA_PSK_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::RSA_PSK_WITH_3DES_EDE_CBC_SHA),
        RSA_PSK_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_128_CBC_SHA),
        RSA_PSK_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_256_CBC_SHA),
        RSA_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::RSA_WITH_SEED_CBC_SHA),
        DH_DSS_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::DH_DSS_WITH_SEED_CBC_SHA),
        DH_RSA_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::DH_RSA_WITH_SEED_CBC_SHA),
        DHE_DSS_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::DHE_DSS_WITH_SEED_CBC_SHA),
        DHE_RSA_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::DHE_RSA_WITH_SEED_CBC_SHA),
        DH_ANON_WITH_SEED_CBC_SHA =>
            Symbol::u16(ciphers::DH_ANON_WITH_SEED_CBC_SHA),
        RSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_AES_128_GCM_SHA256),
        RSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_WITH_AES_256_GCM_SHA384),
        DHE_RSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_128_GCM_SHA256),
        DHE_RSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_256_GCM_SHA384),
        DH_RSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_128_GCM_SHA256),
        DH_RSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_RSA_WITH_AES_256_GCM_SHA384),
        DHE_DSS_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_128_GCM_SHA256),
        DHE_DSS_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_AES_256_GCM_SHA384),
        DH_DSS_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_128_GCM_SHA256),
        DH_DSS_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_DSS_WITH_AES_256_GCM_SHA384),
        DH_ANON_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_128_GCM_SHA256),
        DH_ANON_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_ANON_WITH_AES_256_GCM_SHA384),
        PSK_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_AES_128_GCM_SHA256),
        PSK_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_AES_256_GCM_SHA384),
        DHE_PSK_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_128_GCM_SHA256),
        DHE_PSK_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_256_GCM_SHA384),
        RSA_PSK_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_128_GCM_SHA256),
        RSA_PSK_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_256_GCM_SHA384),
        PSK_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_AES_128_CBC_SHA256),
        PSK_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_AES_256_CBC_SHA384),
        PSK_WITH_NULL_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_NULL_SHA256),
        PSK_WITH_NULL_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_NULL_SHA384),
        DHE_PSK_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_128_CBC_SHA256),
        DHE_PSK_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_256_CBC_SHA384),
        DHE_PSK_WITH_NULL_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_NULL_SHA256),
        DHE_PSK_WITH_NULL_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_NULL_SHA384),
        RSA_PSK_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_128_CBC_SHA256),
        RSA_PSK_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_AES_256_CBC_SHA384),
        RSA_PSK_WITH_NULL_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_NULL_SHA256),
        RSA_PSK_WITH_NULL_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_NULL_SHA384),
        RSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_128_CBC_SHA256),
        DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_128_CBC_SHA256),
        DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_128_CBC_SHA256),
        DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256),
        DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256),
        DH_ANON_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_128_CBC_SHA256),
        RSA_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_256_CBC_SHA256),
        DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_256_CBC_SHA256),
        DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_256_CBC_SHA256),
        DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256),
        DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256),
        DH_ANON_WITH_CAMELLIA_256_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_256_CBC_SHA256),
        SM4_GCM_SM3 =>
            Symbol::u16(ciphers::SM4_GCM_SM3),
        SM4_CCM_SM3 =>
            Symbol::u16(ciphers::SM4_CCM_SM3),
        EMPTY_RENEGOTIATION_INFO_SCSV =>
            Symbol::u16(ciphers::EMPTY_RENEGOTIATION_INFO_SCSV),
        AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::AES_128_GCM_SHA256),
        AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::AES_256_GCM_SHA384),
        CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::CHACHA20_POLY1305_SHA256),
        AES_128_CCM_SHA256 =>
            Symbol::u16(ciphers::AES_128_CCM_SHA256),
        AES_128_CCM_8_SHA256 =>
            Symbol::u16(ciphers::AES_128_CCM_8_SHA256),
        FALLBACK_SCSV =>
            Symbol::u16(ciphers::FALLBACK_SCSV),
        ECDH_ECDSA_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_NULL_SHA),
        ECDH_ECDSA_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_RC4_128_SHA),
        ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA),
        ECDH_ECDSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_128_CBC_SHA),
        ECDH_ECDSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_256_CBC_SHA),
        ECDHE_ECDSA_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_NULL_SHA),
        ECDHE_ECDSA_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_RC4_128_SHA),
        ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA),
        ECDHE_ECDSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
        ECDHE_ECDSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
        ECDH_RSA_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_NULL_SHA),
        ECDH_RSA_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_RC4_128_SHA),
        ECDH_RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_3DES_EDE_CBC_SHA),
        ECDH_RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_128_CBC_SHA),
        ECDH_RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_256_CBC_SHA),
        ECDHE_RSA_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_NULL_SHA),
        ECDHE_RSA_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_RC4_128_SHA),
        ECDHE_RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_3DES_EDE_CBC_SHA),
        ECDHE_RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_128_CBC_SHA),
        ECDHE_RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_256_CBC_SHA),
        ECDH_ANON_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDH_ANON_WITH_NULL_SHA),
        ECDH_ANON_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDH_ANON_WITH_RC4_128_SHA),
        ECDH_ANON_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ANON_WITH_3DES_EDE_CBC_SHA),
        ECDH_ANON_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ANON_WITH_AES_128_CBC_SHA),
        ECDH_ANON_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDH_ANON_WITH_AES_256_CBC_SHA),
        SRP_SHA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_WITH_3DES_EDE_CBC_SHA),
        SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA),
        SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA),
        SRP_SHA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_WITH_AES_128_CBC_SHA),
        SRP_SHA_RSA_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_RSA_WITH_AES_128_CBC_SHA),
        SRP_SHA_DSS_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_DSS_WITH_AES_128_CBC_SHA),
        SRP_SHA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_WITH_AES_256_CBC_SHA),
        SRP_SHA_RSA_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_RSA_WITH_AES_256_CBC_SHA),
        SRP_SHA_DSS_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::SRP_SHA_DSS_WITH_AES_256_CBC_SHA),
        ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
        ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
        ECDH_ECDSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_128_CBC_SHA256),
        ECDH_ECDSA_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_256_CBC_SHA384),
        ECDHE_RSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_128_CBC_SHA256),
        ECDHE_RSA_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_256_CBC_SHA384),
        ECDH_RSA_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_128_CBC_SHA256),
        ECDH_RSA_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_256_CBC_SHA384),
        ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        ECDH_ECDSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_128_GCM_SHA256),
        ECDH_ECDSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_AES_256_GCM_SHA384),
        ECDHE_RSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        ECDHE_RSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        ECDH_RSA_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_128_GCM_SHA256),
        ECDH_RSA_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_AES_256_GCM_SHA384),
        ECDHE_PSK_WITH_RC4_128_SHA =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_RC4_128_SHA),
        ECDHE_PSK_WITH_3DES_EDE_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_3DES_EDE_CBC_SHA),
        ECDHE_PSK_WITH_AES_128_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_128_CBC_SHA),
        ECDHE_PSK_WITH_AES_256_CBC_SHA =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_256_CBC_SHA),
        ECDHE_PSK_WITH_AES_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_128_CBC_SHA256),
        ECDHE_PSK_WITH_AES_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_256_CBC_SHA384),
        ECDHE_PSK_WITH_NULL_SHA =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_NULL_SHA),
        ECDHE_PSK_WITH_NULL_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_NULL_SHA256),
        ECDHE_PSK_WITH_NULL_SHA384 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_NULL_SHA384),
        RSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_ARIA_128_CBC_SHA256),
        RSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::RSA_WITH_ARIA_256_CBC_SHA384),
        DH_DSS_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_ARIA_128_CBC_SHA256),
        DH_DSS_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DH_DSS_WITH_ARIA_256_CBC_SHA384),
        DH_RSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_ARIA_128_CBC_SHA256),
        DH_RSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DH_RSA_WITH_ARIA_256_CBC_SHA384),
        DHE_DSS_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_ARIA_128_CBC_SHA256),
        DHE_DSS_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_ARIA_256_CBC_SHA384),
        DHE_RSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_ARIA_128_CBC_SHA256),
        DHE_RSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_ARIA_256_CBC_SHA384),
        DH_ANON_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_ARIA_128_CBC_SHA256),
        DH_ANON_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DH_ANON_WITH_ARIA_256_CBC_SHA384),
        ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256),
        ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384),
        ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256),
        ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384),
        ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_ARIA_128_CBC_SHA256),
        ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_ARIA_256_CBC_SHA384),
        ECDH_RSA_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_ARIA_128_CBC_SHA256),
        ECDH_RSA_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_ARIA_256_CBC_SHA384),
        RSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_ARIA_128_GCM_SHA256),
        RSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_WITH_ARIA_256_GCM_SHA384),
        DHE_RSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_ARIA_128_GCM_SHA256),
        DHE_RSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_ARIA_256_GCM_SHA384),
        DH_RSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_ARIA_128_GCM_SHA256),
        DH_RSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_RSA_WITH_ARIA_256_GCM_SHA384),
        DHE_DSS_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_ARIA_128_GCM_SHA256),
        DHE_DSS_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_ARIA_256_GCM_SHA384),
        DH_DSS_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_ARIA_128_GCM_SHA256),
        DH_DSS_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_DSS_WITH_ARIA_256_GCM_SHA384),
        DH_ANON_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_ARIA_128_GCM_SHA256),
        DH_ANON_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_ANON_WITH_ARIA_256_GCM_SHA384),
        ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256),
        ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384),
        ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256),
        ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384),
        ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_ARIA_128_GCM_SHA256),
        ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_ARIA_256_GCM_SHA384),
        ECDH_RSA_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_ARIA_128_GCM_SHA256),
        ECDH_RSA_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_ARIA_256_GCM_SHA384),
        PSK_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_ARIA_128_CBC_SHA256),
        PSK_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_ARIA_256_CBC_SHA384),
        DHE_PSK_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_ARIA_128_CBC_SHA256),
        DHE_PSK_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_ARIA_256_CBC_SHA384),
        RSA_PSK_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_ARIA_128_CBC_SHA256),
        RSA_PSK_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_ARIA_256_CBC_SHA384),
        PSK_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_ARIA_128_GCM_SHA256),
        PSK_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_ARIA_256_GCM_SHA384),
        DHE_PSK_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_ARIA_128_GCM_SHA256),
        DHE_PSK_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_ARIA_256_GCM_SHA384),
        RSA_PSK_WITH_ARIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_ARIA_128_GCM_SHA256),
        RSA_PSK_WITH_ARIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_ARIA_256_GCM_SHA384),
        ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_ARIA_128_CBC_SHA256),
        ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_ARIA_256_CBC_SHA384),
        ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256),
        ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384),
        ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256),
        ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384),
        ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256),
        ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384),
        ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256),
        ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384),
        RSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_128_GCM_SHA256),
        RSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_WITH_CAMELLIA_256_GCM_SHA384),
        DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256),
        DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384),
        DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_128_GCM_SHA256),
        DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_RSA_WITH_CAMELLIA_256_GCM_SHA384),
        DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256),
        DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384),
        DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_128_GCM_SHA256),
        DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_DSS_WITH_CAMELLIA_256_GCM_SHA384),
        DH_ANON_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_128_GCM_SHA256),
        DH_ANON_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DH_ANON_WITH_CAMELLIA_256_GCM_SHA384),
        ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256),
        ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384),
        ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256),
        ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384),
        ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256),
        ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384),
        ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256),
        ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384),
        PSK_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_CAMELLIA_128_GCM_SHA256),
        PSK_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_CAMELLIA_256_GCM_SHA384),
        DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256),
        DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384),
        RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256),
        RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384),
        PSK_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_CAMELLIA_128_CBC_SHA256),
        PSK_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::PSK_WITH_CAMELLIA_256_CBC_SHA384),
        DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256),
        DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384),
        RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256),
        RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384),
        ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256),
        ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384),
        RSA_WITH_AES_128_CCM =>
            Symbol::u16(ciphers::RSA_WITH_AES_128_CCM),
        RSA_WITH_AES_256_CCM =>
            Symbol::u16(ciphers::RSA_WITH_AES_256_CCM),
        DHE_RSA_WITH_AES_128_CCM =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_128_CCM),
        DHE_RSA_WITH_AES_256_CCM =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_256_CCM),
        RSA_WITH_AES_128_CCM_8 =>
            Symbol::u16(ciphers::RSA_WITH_AES_128_CCM_8),
        RSA_WITH_AES_256_CCM_8 =>
            Symbol::u16(ciphers::RSA_WITH_AES_256_CCM_8),
        DHE_RSA_WITH_AES_128_CCM_8 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_128_CCM_8),
        DHE_RSA_WITH_AES_256_CCM_8 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_AES_256_CCM_8),
        PSK_WITH_AES_128_CCM =>
            Symbol::u16(ciphers::PSK_WITH_AES_128_CCM),
        PSK_WITH_AES_256_CCM =>
            Symbol::u16(ciphers::PSK_WITH_AES_256_CCM),
        DHE_PSK_WITH_AES_128_CCM =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_128_CCM),
        DHE_PSK_WITH_AES_256_CCM =>
            Symbol::u16(ciphers::DHE_PSK_WITH_AES_256_CCM),
        PSK_WITH_AES_128_CCM_8 =>
            Symbol::u16(ciphers::PSK_WITH_AES_128_CCM_8),
        PSK_WITH_AES_256_CCM_8 =>
            Symbol::u16(ciphers::PSK_WITH_AES_256_CCM_8),
        PSK_DHE_WITH_AES_128_CCM_8 =>
            Symbol::u16(ciphers::PSK_DHE_WITH_AES_128_CCM_8),
        PSK_DHE_WITH_AES_256_CCM_8 =>
            Symbol::u16(ciphers::PSK_DHE_WITH_AES_256_CCM_8),
        ECDHE_ECDSA_WITH_AES_128_CCM =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_128_CCM),
        ECDHE_ECDSA_WITH_AES_256_CCM =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_256_CCM),
        ECDHE_ECDSA_WITH_AES_128_CCM_8 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_128_CCM_8),
        ECDHE_ECDSA_WITH_AES_256_CCM_8 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_AES_256_CCM_8),
        ECCPWD_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECCPWD_WITH_AES_128_GCM_SHA256),
        ECCPWD_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECCPWD_WITH_AES_256_GCM_SHA384),
        ECCPWD_WITH_AES_128_CCM_SHA256 =>
            Symbol::u16(ciphers::ECCPWD_WITH_AES_128_CCM_SHA256),
        ECCPWD_WITH_AES_256_CCM_SHA384 =>
            Symbol::u16(ciphers::ECCPWD_WITH_AES_256_CCM_SHA384),
        SHA256_SHA256 =>
            Symbol::u16(ciphers::SHA256_SHA256),
        SHA384_SHA384 =>
            Symbol::u16(ciphers::SHA384_SHA384),
        GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC),
        GOSTR341112_256_WITH_MAGMA_CTR_OMAC =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_MAGMA_CTR_OMAC),
        GOSTR341112_256_WITH_28147_CNT_IMIT =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_28147_CNT_IMIT),
        GOSTR341112_256_WITH_KUZNYECHIK_MGM_L =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_KUZNYECHIK_MGM_L),
        GOSTR341112_256_WITH_MAGMA_MGM_L =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_MAGMA_MGM_L),
        GOSTR341112_256_WITH_KUZNYECHIK_MGM_S =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_KUZNYECHIK_MGM_S),
        GOSTR341112_256_WITH_MAGMA_MGM_S =>
            Symbol::u16(ciphers::GOSTR341112_256_WITH_MAGMA_MGM_S),
        ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
        ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
        DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
        PSK_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::PSK_WITH_CHACHA20_POLY1305_SHA256),
        ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256),
        DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::DHE_PSK_WITH_CHACHA20_POLY1305_SHA256),
        RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 =>
            Symbol::u16(ciphers::RSA_PSK_WITH_CHACHA20_POLY1305_SHA256),
        ECDHE_PSK_WITH_AES_128_GCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_128_GCM_SHA256),
        ECDHE_PSK_WITH_AES_256_GCM_SHA384 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_256_GCM_SHA384),
        ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_128_CCM_8_SHA256),
        ECDHE_PSK_WITH_AES_128_CCM_SHA256 =>
            Symbol::u16(ciphers::ECDHE_PSK_WITH_AES_128_CCM_SHA256),
    }
};

const TLS_MESSAGE: FuncDef = func! (
    /// Returns a TLS record
    ///
    /// This implements the TLS record framing:
    ///
    /// ```c
    /// struct tls_hdr {
    ///     uint8_t content;
    ///     uint16_t version;
    ///     uint16_t len;
    ///     uint8_t payload[0];
    /// } _packed;
    /// ```
    ///
    /// ### Arguments
    /// * `version: u16` [TLS version](version/README.md)
    /// * `content: u8` The [TLS message type](content/README.md)
    /// * `*payload: Str` the payload bytes
    resynth fn message(
        =>
        version: U16 = version::TLS_1_2,
        content: U8 = content::HANDSHAKE,
        =>
        Str
    ) -> Str
    |mut args| {
        let version: u16 = args.next().into();
        let content: u8 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend(content.to_be_bytes());
        msg.extend(version.to_be_bytes());
        msg.extend((bytes.len() as u16).to_be_bytes());

        /* extensions I guess? */
        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

const TLS_EXTENSION: FuncDef = func! (
    /// Returns a TLS extension
    ///
    /// This implements the TLS extension framing:
    ///
    /// ```c
    /// struct tls_ext {
    ///     uint16_t ext;
    ///     uint16_t len;
    ///     uint8_t payload[0];
    /// } _packed;
    /// ```
    ///
    /// ### Arguments
    /// * `ext: u16` [TLS Extension](ext/README.md)
    /// * `*payload: Str` the payload bytes
    resynth fn extension(
        ext: U16,
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let ext: u16 = args.next().into();
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend(ext.to_be_bytes());
        msg.extend((bytes.len() as u16).to_be_bytes());

        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

fn len24(len: usize) -> [u8; 3] {
    let b = (len as u32).to_be_bytes();
    [b[1], b[2], b[3]]
}

const TLS_CIPHERS: FuncDef = func! (
    /// Returns a TLS ciphers list
    ///
    /// ### Arguments
    /// * `*cipher: u16` the [TLS ciphers](cipher/README.md)
    resynth fn ciphers(
        =>
        =>
        U16
    ) -> Str
    |mut args| {
        let extra: Vec<u16> = args.collect_extra_args();
        let list_len = extra.len() * 2;

        let mut msg: Vec<u8> = Vec::with_capacity(2 + list_len);

        msg.extend((list_len as u16).to_be_bytes());
        for id in extra {
            msg.extend(id.to_be_bytes());
        }

        Ok(Val::str(msg))
    }
);

const TLS_CLIENT_HELLO: FuncDef = func! (
    /// Returns a TLS client hello
    ///
    /// This has to be framed inside a content::HANDSHAKE [message](#message)
    ///
    /// ### Arguments
    /// * `version: u16` Requested [TLS version](version/README.md)
    /// * `sessionid: Str` Session ID, should be a u8 len prefixed buffer
    /// * `ciphers: Str` Supported [ciphers](cipher/README.md) eg. as created with
    ///                  [ciphers()][#ciphers]
    /// * `compression: Str` Supported compression algorithms (pretty much defunct)
    /// * `*extensions: Str` Extensions, eg. as created by [extension()](#extension)
    resynth fn client_hello(
        =>
        version: U16 = version::TLS_1_2,
        sessionid: Str = b"\x00",
        ciphers: Str = b"\x00\x02\x00\x00", // null cipher
        compression: Str = b"\x01\x00", // null compression
        =>
        Str
    ) -> Str
    |mut args| {
        let version: u16 = args.next().into();
        let sessionid: Buf = args.next().into();
        let ciphers: Buf = args.next().into();
        let compression: Buf = args.next().into();
        let extensions: Buf = args.join_extra(b"").into();

        let hlen = 34
            + sessionid.len()
            + ciphers.len()
            + compression.len()
            + if extensions.len() > 0 { 2 } else { 0 }
            + extensions.len();

        let mut msg: Vec<u8> = Vec::with_capacity(4 + hlen);

        /* 4 bytes handshake header */
        msg.push(handshake::CLIENT_HELLO);
        msg.extend(len24(hlen));

        /* 34 bytes version + random */
        msg.extend(version.to_be_bytes());
        msg.extend(b"_client__random__client__random_");

        msg.extend(sessionid.as_ref());
        msg.extend(ciphers.as_ref());
        msg.extend(compression.as_ref());

        if extensions.len() > 0 {
            msg.extend((extensions.len() as u16).to_be_bytes());
            msg.extend(extensions.as_ref());
        }

        Ok(Val::str(msg))
    }
);

const TLS_SERVER_HELLO: FuncDef = func! (
    /// Returns a TLS server hello
    ///
    /// This has to be framed inside a content::HANDSHAKE [message](#message)
    ///
    /// ### Arguments
    /// * `version: u16` Negotiated [TLS version](version/README.md)
    /// * `sessionid: Str` Session ID, should be a u8 len prefixed buffer
    /// * `cipher: u16` Negotiated [ciphers](cipher/README.md)
    /// * `compression: u8` Negotiated compression algorithm (pretty much defunct)
    /// * `*extensions: Str` Extensions, eg. as created by [extension()](#extension)
    resynth fn server_hello(
        =>
        version: U16 = version::TLS_1_2,
        sessionid: Str = b"\x00",
        cipher: U16 = ciphers::NULL_WITH_NULL_NULL,
        compression: U8 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let version: u16 = args.next().into();
        let sessionid: Buf = args.next().into();
        let cipher: u16 = args.next().into();
        let compression: u8 = args.next().into();
        let extensions: Buf = args.join_extra(b"").into();

        let hlen = 34
            + sessionid.len()
            + 2
            + 1
            + if extensions.len() > 0 { 2 } else { 0 }
            + extensions.len();

        let mut msg: Vec<u8> = Vec::with_capacity(4 + hlen);

        /* 4 bytes handshake header */
        msg.push(handshake::SERVER_HELLO);
        msg.extend(len24(hlen));

        /* 34 bytes version + random */
        msg.extend(version.to_be_bytes());
        msg.extend(b"_server__random__server__random_");

        msg.extend(sessionid.as_ref());

        msg.extend(cipher.to_be_bytes());
        msg.push(compression);

        if extensions.len() > 0 {
            msg.extend((extensions.len() as u16).to_be_bytes());
            msg.extend(extensions.as_ref());
        }

        Ok(Val::str(msg))
    }
);

const TLS_SNI: FuncDef = func! (
    /// Returns a TLS SNI extension
    ///
    /// The SNI extension is the Server Name Indictator
    ///
    /// ### Arguments
    /// * `name: Str` Server Names
    resynth fn sni(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let names: Vec<Buf> = args.collect_extra_args();
        let names_len: usize = names.iter().map(|x| -> Buf { x.into() }).map(|x| x.len()).sum();
        let name_list_len = 3 * names.len() + names_len;
        let tot_len = 2 + name_list_len;

        let mut msg: Vec<u8> = Vec::with_capacity(tot_len + 4);

        msg.extend(ext::SERVER_NAME.to_be_bytes());
        msg.extend((tot_len as u16).to_be_bytes());

        msg.extend((name_list_len as u16).to_be_bytes());
        for name in names {
            msg.push(0);
            msg.extend((name.len() as u16).to_be_bytes());
            msg.extend(name.as_ref());
        }

        Ok(Val::str(msg))
    }
);

const TLS_CERTIFICATES: FuncDef = func! (
    /// Returns a chain of X.509 certificates
    resynth fn certificates(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let certs: Vec<Buf> = args.collect_extra_args();
        let certs_len: usize = certs.iter().map(|x| -> Buf { x.into() }).map(|x| x.len()).sum();
        let cert_list_len = 3 * certs.len() + certs_len;
        let tot_len = 3 + cert_list_len;

        let mut msg: Vec<u8> = Vec::with_capacity(tot_len + 4);

        msg.push(handshake::CERTIFICATE);
        msg.extend(len24(tot_len));

        msg.extend(len24(cert_list_len));
        for cert in certs {
            msg.extend(len24(cert.len()));
            msg.extend(cert.as_ref());
        }

        Ok(Val::str(msg))
    }
);

pub const TLS: Module = module! {
    /// # Transport Layer Security (TLS)
    ///
    /// ## Example
    /// ```resynth
    /// import io;
    /// import ipv4;
    /// import std;
    /// import tls;
    ///
    /// let tls = ipv4::tcp::flow(
    ///   192.168.106.72:40015,
    ///   172.16.14.121:443,
    /// );
    ///
    /// tls.open();
    ///
    /// // Client Hello
    /// tls.client_message(
    ///   tls::message(
    ///     content: tls::content::HANDSHAKE,
    ///     version: tls::version::TLS_1_0,
    ///     tls::client_hello(
    ///       ciphers: tls::ciphers(
    ///         tls::cipher::ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ///         tls::cipher::ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ///         tls::cipher::ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ///         tls::cipher::ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ///         tls::cipher::ECDHE_ECDSA_WITH_AES_256_CCM,
    ///         tls::cipher::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ///         tls::cipher::ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ///         tls::cipher::ECDHE_ECDSA_WITH_AES_128_CCM,
    ///         tls::cipher::ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    ///         tls::cipher::ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    ///         tls::cipher::ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    ///         tls::cipher::ECDHE_RSA_WITH_AES_256_CBC_SHA,
    ///         tls::cipher::ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    ///         tls::cipher::ECDHE_RSA_WITH_AES_128_CBC_SHA,
    ///         tls::cipher::RSA_WITH_AES_256_GCM_SHA384,
    ///         tls::cipher::RSA_WITH_AES_256_CCM,
    ///         tls::cipher::RSA_WITH_AES_128_GCM_SHA256,
    ///         tls::cipher::RSA_WITH_AES_128_CCM,
    ///         tls::cipher::RSA_WITH_AES_256_CBC_SHA256,
    ///         tls::cipher::RSA_WITH_AES_128_CBC_SHA256,
    ///         tls::cipher::RSA_WITH_AES_256_CBC_SHA,
    ///         tls::cipher::RSA_WITH_AES_128_CBC_SHA,
    ///         tls::cipher::DHE_RSA_WITH_AES_256_GCM_SHA384,
    ///         tls::cipher::DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ///         tls::cipher::DHE_RSA_WITH_AES_256_CCM,
    ///         tls::cipher::DHE_RSA_WITH_AES_128_GCM_SHA256,
    ///         tls::cipher::DHE_RSA_WITH_AES_128_CCM,
    ///         tls::cipher::DHE_RSA_WITH_AES_256_CBC_SHA256,
    ///         tls::cipher::DHE_RSA_WITH_AES_128_CBC_SHA256,
    ///         tls::cipher::DHE_RSA_WITH_AES_256_CBC_SHA,
    ///         tls::cipher::DHE_RSA_WITH_AES_128_CBC_SHA,
    ///         tls::cipher::EMPTY_RENEGOTIATION_INFO_SCSV,
    ///       ),
    ///       version: tls::version::TLS_1_2,
    ///
    ///       tls::sni("test.local"),
    ///
    ///       tls::extension(
    ///         tls::ext::EC_POINT_FORMATS,
    ///         std::len_u8(
    ///           "|00 01 02|",
    ///         )
    ///       ),
    ///
    ///       tls::extension(
    ///         tls::ext::SUPPORTED_GROUPS,
    ///         std::len_be16(
    ///           "|00 1d 00 17 00 1e 00 19 00 18|",
    ///         ),
    ///       ),
    ///
    ///       tls::extension(
    ///         tls::ext::SESSION_TICKET,
    ///       ),
    ///
    ///       tls::extension(
    ///         tls::ext::ENCRYPT_THEN_MAC,
    ///       ),
    ///
    ///       tls::extension(
    ///         tls::ext::EXTENDED_MASTER_SECRET,
    ///       ),
    ///
    ///       tls::extension(
    ///         tls::ext::SIGNATURE_ALGORITHMS,
    ///         std::len_be16(
    ///           "|04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b|",
    ///           "|08 04 08 05 08 06 04 01 05 01 06 01 03 03 03 01|",
    ///         ),
    ///       ),
    ///
    ///       tls::extension(
    ///         tls::ext::ALPN,
    ///         std::len_be16(
    ///           std::len_u8("postgresql"),
    ///           std::len_u8("http/0.9"),
    ///           std::len_u8("imap"),
    ///           std::len_u8("pop3"),
    ///           std::len_u8("h2"),
    ///         ),
    ///       ),
    ///     )
    ///   ),
    /// );
    ///
    /// tls.server_message(
    ///   tls::message(
    ///     content: tls::content::HANDSHAKE,
    ///     version: tls::version::TLS_1_2,
    ///     tls::server_hello(
    ///       version: tls::version::TLS_1_2,
    ///       cipher: tls::cipher::ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ///       tls::extension(
    ///         tls::ext::RENEGOTIATION_INFO,
    ///         std::u8(0),
    ///       ),
    ///       tls::extension(
    ///         tls::ext::EC_POINT_FORMATS,
    ///         std::len_u8(
    ///           std::u8(0),
    ///           std::u8(1),
    ///           std::u8(2),
    ///         ),
    ///       ),
    ///       tls::extension(
    ///         tls::ext::SESSION_TICKET,
    ///       ),
    ///       tls::extension(
    ///         tls::ext::EXTENDED_MASTER_SECRET,
    ///       ),
    ///       tls::extension(
    ///         tls::ext::ALPN,
    ///         std::len_be16(
    ///           std::len_u8("http/0.9"),
    ///           std::len_u8("pop3"),
    ///         ),
    ///       ),
    ///     ),
    ///   ),
    ///
    ///
    ///   tls::message(
    ///     content: tls::content::HANDSHAKE,
    ///     version: tls::version::TLS_1_2,
    ///     tls::certificates(
    ///       io::file("./example-data/rsa4096.x509.cert.der"),
    ///     )
    ///   ),
    ///
    ///   // Server Key Exchange
    ///   tls::message(
    ///     content: tls::content::HANDSHAKE,
    ///     version: tls::version::TLS_1_2,
    ///     tls::handshake::SERVER_KEY_EXCHANGE,
    ///     "|00 02 28 03 00 1d 20 2f b5 e1 12 ca 8a de fc 9b c9 96 ed eb 63 8e df e5|",
    ///     "|aa 96 57 cd 0f 39 7c 46 b0 18 49 b3 48 3c 70 08 04 02 00 42 27 29 90 25|",
    ///     "|ef a9 ab 29 b2 ec d2 24 6b f7 9a cc 1e 2a 49 44 93 fb b6 0a 75 51 40 40|",
    ///     "|90 45 d2 fb d2 c7 0a be 68 5b 90 45 c2 00 19 29 b5 6f 70 0c cb b6 c6 15|",
    ///     "|fb 1c 4a fe 48 10 d2 d0 de a3 1d 54 7f 8f 5f 93 5c 71 68 77 6b 60 62 d2|",
    ///     "|6c 4c 8f 05 00 61 f1 18 0e 6a e8 18 99 3e 44 b6 b9 52 d0 cb 70 dd ad 50|",
    ///     "|01 af 07 98 a3 7b 13 4c c8 21 cb f5 54 14 d3 b3 ee 76 5b ce cb f7 ac a6|",
    ///     "|49 f9 6f 2b ec e0 5b 3e 4c f3 22 88 f9 00 1c 5d 20 91 31 64 ed 85 48 03|",
    ///     "|c7 8b 41 14 4d 04 5d 68 92 ca 21 09 c0 2d bc dd 00 74 26 7d 85 45 6a 44|",
    ///     "|c9 82 36 19 b3 d3 3b 34 10 7f b9 7c e1 23 a1 1b 35 5f 1f 73 57 3d 9b c2|",
    ///     "|d2 20 92 ac 22 cb ac 82 15 1a 7c 64 ae 93 c0 e0 03 c1 87 9c c5 ff c2 3d|",
    ///     "|1b d7 d6 22 44 eb c2 a5 81 b0 11 71 c0 ac 47 3d 6e 2c b3 61 7d d0 13 df|",
    ///     "|4f a5 5b bd 60 c0 cf 94 3c de de 19 c3 07 04 55 b7 c2 3a ca 90 33 0c 9f|",
    ///     "|e5 ee b5 35 37 f9 b8 9c 0c 9e 8c 1e f2 15 56 05 fc af 77 a1 81 6c 7a c8|",
    ///     "|27 fa ac 54 aa 2e 19 75 fe 71 2b bf f6 be 16 6d c3 46 09 97 65 36 b5 45|",
    ///     "|45 37 eb 5b b9 b2 f9 58 d4 50 45 d7 86 ae 45 8f 57 54 79 b8 14 1c 70 26|",
    ///     "|45 18 01 47 d6 9b e2 a8 0c 50 73 15 9a 52 c6 c1 15 ce 61 33 1f 6e a6 99|",
    ///     "|38 39 29 31 29 eb da 82 5e 86 cc 4a f1 9c d2 ad 26 7d ac ed 54 0f e2 07|",
    ///     "|32 05 22 9a bf 57 b2 7d 53 e8 7f ce 9c 0c ed b6 02 2c ab 6a 2d 14 20 96|",
    ///     "|ca de eb 55 d4 17 83 30 c2 da df 7c 59 f9 7c 08 c2 14 37 0a 30 b5 94 13|",
    ///     "|34 c2 a5 12 1d 11 c4 77 40 e4 d9 a1 5e b4 7e 2a a9 14 06 c1 57 2e 02 f3|",
    ///     "|7d 05 9e 07 70 a7 2b fc 41 a4 db 7e ae 7b 34 1f cd 05 43 ed 15 06 72 6d|",
    ///     "|f2 82 1c 9d 94 a3 87 97 7f 09 7b 38 c3 8b 10 93 e5 0a 11 1e 24 0f e7 0a|",
    ///     "|ce e8 35|"
    ///   ),
    ///
    ///   // Server Hello Done
    ///   tls::message(
    ///     content: tls::content::HANDSHAKE,
    ///     version: tls::version::TLS_1_2,
    ///     tls::handshake::SERVER_HELLO_DONE,
    ///     "|00 00 00|"
    ///   ),
    /// );
    /// ```
    resynth mod tls {
        version => Symbol::Module(&VERSION),
        content => Symbol::Module(&CONTENT),
        handshake => Symbol::Module(&HANDSHAKE),
        ext => Symbol::Module(&EXT),
        cipher => Symbol::Module(&CIPHER),

        message => Symbol::Func(&TLS_MESSAGE),
        extension => Symbol::Func(&TLS_EXTENSION),
        client_hello => Symbol::Func(&TLS_CLIENT_HELLO),
        server_hello => Symbol::Func(&TLS_SERVER_HELLO),
        ciphers => Symbol::Func(&TLS_CIPHERS),
        certificates => Symbol::Func(&TLS_CERTIFICATES),
        sni => Symbol::Func(&TLS_SNI),
    }
};
