namespace WireGuard.NET.Protocol;

/// <summary>
/// WireGuard protocol constants: cryptographic primitive sizes, message layout lengths, message
/// type discriminants, and session timer/limit values, as specified by the WireGuard whitepaper.
/// </summary>
public static class WireGuardConstants
{
    /// <summary>Size in bytes of WireGuard keys (X25519 public/private keys and preshared keys).</summary>
    public const int WG_KEY_LEN = 32;
    /// <summary>Size in bytes of the ChaCha20Poly1305 nonce used for AEAD encryption.</summary>
    public const int WG_AEAD_NONCE_LEN = 12;
    /// <summary>Size in bytes of the Poly1305 authentication tag appended to AEAD ciphertexts.</summary>
    public const int WG_AEAD_TAG_LEN = 16;
    /// <summary>Size in bytes of each of the mac1 and mac2 fields of handshake messages.</summary>
    public const int WG_COOKIE_MAC_LEN = 16;
    /// <summary>Size in bytes of the nonce carried in a cookie reply message.</summary>
    public const int WG_COOKIE_NONCE_LEN = 24;
    /// <summary>Size in bytes of the key used to encrypt cookie replies (HASH("cookie--" || public key)).</summary>
    public const int WG_COOKIE_KEY_LEN = 32;
    /// <summary>Size in bytes of the cookie value exchanged by the cookie mechanism.</summary>
    public const int WG_COOKIE_LEN = 16;

    /// <summary>Size in bytes of a Noise protocol public key.</summary>
    public const int NOISE_PUBLIC_KEY_LEN = 32;
    /// <summary>Size in bytes of a Noise protocol authentication tag.</summary>
    public const int NOISE_AUTHTAG_LEN = 16;
    /// <summary>Size in bytes of a TAI64N timestamp (used to reject replayed handshake initiations).</summary>
    public const int NOISE_TAI64N_LEN = 12;
    /// <summary>Size in bytes of a Noise hash output (BLAKE2s-256).</summary>
    public const int NOISE_HASH_LEN = 32;

    /// <summary>Size in bytes of the leading message-type field shared by all message types.</summary>
    public const int MESSAGE_HEADER_LEN = 4;
    /// <summary>Size in bytes of the message-type field.</summary>
    public const int MESSAGE_TYPE_LEN = 4;
    /// <summary>Size in bytes of a sender or receiver session-index field.</summary>
    public const int MESSAGE_INDEX_LEN = 4;
    /// <summary>Size in bytes of the per-packet counter field of a transport data packet.</summary>
    public const int MESSAGE_COUNTER_LEN = 8;

    /// <summary>
    /// Total size in bytes of a handshake initiation message:
    /// type (4) | sender index (4) | unencrypted ephemeral (32) | encrypted static (32 + 16 tag) |
    /// encrypted timestamp (12 + 16 tag) | mac1 (16) | mac2 (16).
    /// </summary>
    public const int HANDSHAKE_INITIATION_LEN = 148;
    /// <summary>
    /// Total size in bytes of a handshake response message:
    /// type (4) | sender index (4) | receiver index (4) | unencrypted ephemeral (32) |
    /// encrypted-nothing tag (0 + 16) | mac1 (16) | mac2 (16).
    /// </summary>
    public const int HANDSHAKE_RESPONSE_LEN = 92;
    /// <summary>
    /// Total size in bytes of a cookie reply message:
    /// type (4) | receiver index (4) | nonce (24) | encrypted cookie (16 + 16 tag).
    /// </summary>
    public const int COOKIE_REPLY_LEN = 64;
    /// <summary>
    /// Minimum size in bytes of a transport data packet:
    /// type (4) | receiver index (4) | counter (8).
    /// </summary>
    public const int DATA_PACKET_MIN_LEN = 16;

    /// <summary>Message-type discriminant for handshake initiation messages.</summary>
    public const uint TYPE_INITIATION = 1;
    /// <summary>Message-type discriminant for handshake response messages.</summary>
    public const uint TYPE_RESPONSE = 2;
    /// <summary>Message-type discriminant for cookie reply messages.</summary>
    public const uint TYPE_COOKIE = 3;
    /// <summary>Message-type discriminant for transport data packets.</summary>
    public const uint TYPE_DATA = 4;

    /// <summary>Seconds after which an established session initiates rekeying (REKEY_AFTER_TIME).</summary>
    public const int REKEY_AFTER_TIME = 180;
    /// <summary>Message count after which an established session initiates rekeying (REKEY_AFTER_MESSAGES, 2^60).</summary>
    public const ulong REKEY_AFTER_MESSAGES = 1UL << 60;
    /// <summary>Seconds after which a session is rejected and a new handshake is required (REJECT_AFTER_TIME).</summary>
    public const int REJECT_AFTER_TIME = 600;
    /// <summary>Message count after which a session is rejected (REJECT_AFTER_MESSAGES, 2^64 - 2^4 - 1).</summary>
    public const ulong REJECT_AFTER_MESSAGES = unchecked((1UL << 64) - (1UL << 4) - 1);
    /// <summary>Seconds a handshake attempt is retried before giving up (REKEY_ATTEMPT_TIME).</summary>
    public const int REKEY_ATTEMPT_TIME = 90;

    /// <summary>Seconds of transmission silence after which an idle session sends a keepalive.</summary>
    public const int KEEPALIVE_TIMEOUT = 10;
    /// <summary>Lifetime in seconds of a cookie before it is rotated.</summary>
    public const int COOKIE_SECRET_TIME = 120;

    /// <summary>Maximum number of handshake initiation attempts before declaring the handshake failed.</summary>
    public const int MAX_HANDSHAKE_ATTEMPTS = 5;
    /// <summary>Timeout in seconds for an individual handshake exchange.</summary>
    public const int HANDSHAKE_TIMEOUT_SECONDS = 5;

    /// <summary>
    /// Size in bytes of an initiation message between its 8-byte header and the trailing MACs:
    /// unencrypted ephemeral (32) | encrypted static (32 + 16 tag) | encrypted timestamp (12 + 16 tag).
    /// </summary>
    public const int INITIATION_NOISE_PAYLOAD_LEN = 108;
    /// <summary>
    /// Size in bytes of a response message between its 12-byte header and the trailing MACs:
    /// unencrypted ephemeral (32) | encrypted-nothing tag (16).
    /// </summary>
    public const int RESPONSE_NOISE_PAYLOAD_LEN = 48;

    /// <summary>Initiation header size in bytes: message type (4) + sender index (4).</summary>
    public const int INITIATION_HEADER_LEN = MESSAGE_TYPE_LEN + MESSAGE_INDEX_LEN;
    /// <summary>Response header size in bytes: message type (4) + sender index (4) + receiver index (4).</summary>
    public const int RESPONSE_HEADER_LEN = MESSAGE_TYPE_LEN + MESSAGE_INDEX_LEN * 2;
}
