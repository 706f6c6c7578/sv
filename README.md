# sv
Generate, sign and verify messages, with Ed25519 key pairs.

Usage: sv [genkey|sign|verify] [message file] [key file]

The Signature Marker for messages is: ----Ed25518 Signature----. If this
is also found in your text message and not at the end of a message,
a Signature error will occurs. Sorry about that.
