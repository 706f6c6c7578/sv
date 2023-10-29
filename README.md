# sv
Generate, sign and verify messages, with Ed25519 key pairs.

Usage: sv [genkey|sign|verify] [message file] [key file] [-l line length]

The Signature Marker equals email or Usenet Signature Markers. When -l
is not used, one long Signature line will be produced.

Please note: A Signature error can occur if your Message contains
also Signature Markers, like '-- '. You may change this in the
Code to something else, but beware this is not GnuPG, where this
probably does not matter.
