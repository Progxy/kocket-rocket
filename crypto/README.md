# Crypto Stack

The security of the communication will be provided via the following algorithms:

 - First the message will be signed using Ed25519;
 - The resulting message + signature are then encoded with a OTK using ChaCha20-Poly1305;
 - Finally, the OTK will be encrypted the shared key previously derived using X25519.

## Resources

 - [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) - (Ed25519).
 - [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) - (ChaCha20-Poly1305).
 - [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) - (X25519).
