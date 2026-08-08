# JA4 TLS fingerprint server

## Goal

Build a small Go HTTPS server that observes the real TLS ClientHello sent by a
client, calculates its JA4 TLS fingerprint, and returns the result to the
client. We will build it slowly in small, reviewable commits.

The first useful version is a development and learning tool, not a production
service.

## Core requirements

1. The project is written in Go.
2. The server listens for HTTPS connections over TCP.
3. It reads the real ClientHello bytes sent by the connecting client. It must
   not infer a fingerprint from the User-Agent header or use a mocked browser
   profile.
4. It calculates JA4 according to the published JA4 TLS client fingerprint
   specification.
5. GREASE values are ignored where required by the JA4 specification.
6. After inspecting the ClientHello, the server completes the TLS handshake and
   serves an HTTP response. Inspecting the handshake must not prevent the
   connection from continuing.
7. A basic endpoint returns at least the full JA4 fingerprint as JSON.
8. Invalid, incomplete, oversized, or slow ClientHello messages fail safely and
   do not crash or indefinitely block the server.
9. Server settings such as listen address and certificate paths are
   configurable; useful local-development defaults may be added later.
10. The code is split into small packages with parsing and fingerprinting logic
    independent from the network server.

Example response (the value is illustrative):

```json
{
  "ja4": "t13d1516h2_8daaf6152771_02713d6af862"
}
```

## Run the HTTPS server locally

Generate a self-signed development certificate and start the server using its
default paths:

```sh
./scripts/generate-cert.sh
go run .
```

The generated certificate is for local development and is not trusted by
clients automatically.

## Testing requirements

Testing will have two layers:

- Fast tests use captured ClientHello fixtures to test parsing, malformed input,
  GREASE handling, and known JA4 results. These tests make development reliable,
  but do not replace real-client tests.
- End-to-end tests start the actual server and launch actual client programs.
  The planned client matrix includes curl, Firefox, and Chrome/Chromium. A
  Firefox test must start Firefox itself; it must not substitute a library that
  imitates Firefox's TLS profile. The same rule applies to Chrome/Chromium.

Browser versions can change their fingerprints. Therefore, end-to-end tests
should primarily prove that a real handshake succeeds and that a valid JA4 is
returned. Any exact expected fingerprint must be tied to a recorded browser and
platform version.

## Test-driven development

New behavior will normally be developed with a red-green-refactor cycle:

1. **Red:** write the smallest test that describes the next required behavior
   and confirm that it fails for the expected reason.
2. **Green:** add only enough implementation to make that test pass.
3. **Refactor:** improve the code without changing behavior while keeping all
   tests passing.

The failing red state is a local development step, not a commit. Each completed
commit should contain its tests and implementation together and leave the
relevant test suite passing.

Tests should describe externally observable behavior rather than copy internal
implementation details. Captured ClientHello files can be used as realistic
fixtures, while small constructed inputs should cover individual edge cases.
Code that only connects existing tested components may use a focused integration
test instead of an artificial unit test.

## Out of scope for the first version

- Identifying a browser or assigning a browser name from a JA4 value.
- A database of known fingerprints.
- JA4+ fingerprints other than JA4, such as JA4H or JA4S.
- QUIC/HTTP/3 (`q` transport fingerprints); the first version supports TLS over
  TCP (`t`).
- Production concerns such as authentication, rate limiting, persistent
  storage, proxy protocol support, and distributed deployment.
- Automated Firefox and Chrome/Chromium tests in the earliest commits. They are
  a later milestone after the server and fast tests are stable.

## Build plan: small commits

Each numbered item is intended to be one small commit. We will complete and
verify one item before starting the next. For behavior changes, follow the
red-green-refactor cycle before preparing the commit.

1. **Document the requirements**
   Keep this file as the agreed scope and build order.

2. **Clean the prototype and create a minimal baseline — completed**
   Replaced the experimental server with the smallest valid Go program. Removed
   generated captures and unused empty scaffolding directories. Retained one
   ClientHello and TLS-record pair in `testdata`, together with its recorded JA4
   value and provenance notes. Added `.gitignore` rules for local Go output,
   generated captures, and development certificates. Verified the minimal
   project with local Go test, vet, and build commands. No JA4 behavior was added.

3. **Define the ClientHello data model — completed**
   Added an internal `ClientHello` type containing the ordered TLS versions,
   cipher suites, extension IDs, SNI presence, ALPN protocols, and signature
   algorithms needed by JA4. The model preserves wire values and contains no
   parsing, networking, GREASE filtering, sorting, or fingerprint calculation.

4. **Parse the TLS record and handshake headers — completed**
   Added a bounded TLS-record reader that returns one complete ClientHello,
   including its handshake header, when input spans one or multiple records.
   Test-first coverage uses the retained real fixture and constructed inputs for
   fragmentation, truncated headers and payloads, invalid record and handshake
   types, invalid record versions, and byte-limit enforcement.

5. **Parse the ClientHello fields used by JA4 — completed**
   Added a bounds-checked parser for TLS versions, cipher suites, extension IDs,
   SNI presence, ALPN protocols, and signature algorithms. Test-first coverage
   verifies ordered field extraction, every truncated prefix, malformed
   JA4-specific vectors, and successful parsing of the retained real fixture.

6. **Calculate the human-readable JA4 `a` section — completed**
   Added the ten-character TLS-over-TCP `a` section with effective TLS-version
   selection, SNI marker, GREASE-aware cipher and extension counts capped at 99,
   and specification-compliant ASCII or hexadecimal ALPN markers. Tests cover
   version mappings, count and ALPN edge cases, and the retained real fixture.

7. **Calculate the JA4 `b` and `c` sections — completed**
   Added sorted lowercase hexadecimal inputs, GREASE filtering, SHA-256
   truncation, specification-defined empty hashes, and complete fingerprint
   assembly. Tests verify the official JA4 example, the retained real fixture,
   ordering rules, signature-order sensitivity, and input immutability. The
   package now calculates a complete JA4 without a server.

8. **Capture ClientHello without consuming the connection — completed**
   Added a tee-and-replay connection wrapper that returns the inspected
   ClientHello while preserving every consumed byte for Go's TLS server. Tests
   verify byte-for-byte replay of the retained record fixture and completion of
   a real in-memory TLS client/server handshake on the inspected connection.

9. **Serve HTTPS — completed**
   Added a configurable HTTPS server that loads certificate files, inspects and
   completes TLS connections, and returns a basic HTTP response. It requires
   finite ClientHello, handshake, header-read, write, and idle limits; drops bad
   or slow handshakes without stopping the listener; and supports graceful
   shutdown. The command exposes local flags and handles interrupt/termination
   signals. A local OpenSSL script creates a self-signed certificate at the
   command's default certificate paths and refuses to overwrite an existing
   private key. Network-level tests cover HTTPS, timeout recovery, and shutdown.

10. **Return JA4 as JSON — completed**
    Connected each accepted TLS connection's captured ClientHello to the parser
    and fingerprint package, carried the result through the HTTP connection
    context, and returned it from the endpoint as `{"ja4":"..."}`. An
    end-to-end Go TLS client test verifies HTTPS, JSON content type, response
    decoding, and the complete JA4 format.

11. **Add a real curl test — completed**
    Added an end-to-end test that starts the actual HTTPS server on an ephemeral
    loopback port, invokes the installed curl executable, decodes its JSON
    response, and validates the complete JA4 format. It skips with a clear
    message only when curl is not installed.

12. **Add a real Firefox test**
    Launch an installed Firefox in an isolated temporary profile, visit the
    server, collect the response, and shut the browser down reliably. Skip with
    a clear message when Firefox is not installed.

13. **Add a real Chrome/Chromium test**
    Launch an installed Chrome or Chromium with an isolated temporary profile
    and apply the same checks and cleanup rules as Firefox.

14. **Add local documentation**
    Document how to create local certificates, start the server, run the fast
    tests, and run each real-client test. Browser tests run locally only when
    the corresponding real browser is installed.

## Working agreement

- Do only the current numbered step unless we explicitly agree to expand it.
- Before each implementation step, state what the commit will contain.
- After each step, run the relevant checks and review the diff.
- Develop new behavior test-first unless the step only changes documentation or
  project structure.
- After the relevant checks pass, Codex stages all files belonging to the
  completed numbered step and creates its Git commit automatically.
- Prefer a sequence of small working changes over a large rewrite.
- Keep builds and tests local. CI/CD configuration is not required for this
  project.

## Existing prototype

The repository originally contained a single-file prototype that captured a
ClientHello, calculated a fingerprint, wrote capture files, and then closed the
connection. During step 2, that experimental implementation and its generated
output were removed. One capture was deliberately retained in `testdata` as a
future test fixture, and the project now starts from a minimal buildable Go
program.
