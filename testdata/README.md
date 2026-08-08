# Captured ClientHello fixture

This directory contains one TLS ClientHello captured by the original prototype.
It is retained as realistic input for future parser and JA4 tests.

- `tls_records.bin` contains the TLS record header and payload.
- `clienthello.bin` contains the extracted ClientHello handshake message.
- `ja4.txt` contains the JA4 value produced by the prototype.

The client program and version that created this capture were not recorded, so
the fixture must not be presented as a known browser fingerprint. Its expected
JA4 value must be checked against the published JA4 specification before it is
used as an authoritative test result.
