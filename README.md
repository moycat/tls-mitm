# tls-mitm

`tls-mitm` is a Rust command-line proxy for authorized TLS testing of devices and applications. It reads the SNI from a client's TLS ClientHello, uses a configured CA to sign a server certificate with the matching DNS SAN, and forwards decrypted application bytes to the upstream service in both directions. Per-domain routes can instead connect to a plain TCP upstream. The forwarding layer is independent of HTTP, so HTTP/1.1, HTTP/2, and other protocols over TLS can pass through it. Optional services can rewrite DNS answers and stream decrypted traffic as PCAP.

## Build and configure

Building requires Rust. Certificate signing and the certificate tests require the `openssl` command on Linux or macOS. The supplied CA private key must be an unencrypted PEM file. `proxy.ca_cert` may be a PEM certificate chain: its first certificate must be the issuing CA that matches `proxy.ca_key`, followed by its issuers in signing order. The proxy sends this chain with each generated leaf certificate. It does not perform an additional OpenSSL chain-verification step after signing; the test device must trust the corresponding root CA or an intermediate CA explicitly installed as a trust anchor. The included CA and key are test fixtures only. Never distribute the CA private key to test devices.

```sh
cargo build --release
```

All runtime settings are in TOML. The included [example/config.toml](example/config.toml) uses the repository's test CA and listens on local port 443, which may require elevated privileges. From the repository root, the program reads `example/config.toml` by default. For machine-specific CA paths or settings, create the ignored `config.local.toml` and pass it with `--config`. Relative certificate and capture-output paths resolve against the configuration file's directory. The inline `[proxy]` examples below assume a configuration file in the repository root; the bundled example uses `certs/` paths relative to `example/config.toml`.

```sh
./target/release/tls-mitm
# Or specify the bundled example explicitly:
./target/release/tls-mitm --config example/config.toml
# Or use a local configuration file:
./target/release/tls-mitm --config config.local.toml
```

A minimal configuration can use an unprivileged local port:

```toml
[proxy]
ca_cert = "example/certs/test.crt.pem"
ca_key = "example/certs/test.key.pem"
listen = ["127.0.0.1:8443"]
upstream_port = 443
resolver = "1.1.1.1:53"
```

For a manual check against an authorized, reachable upstream, replace `example.com` with its hostname. The hostname in the URL becomes the SNI; `--resolve` sends the client connection to the local proxy. With `upstream_port = 443`, the proxy connects to that hostname on port 443.

```sh
curl --cacert example/certs/test.crt.pem \
  --resolve example.com:8443:127.0.0.1 \
  https://example.com:8443/
```

`proxy.resolver` is the proxy's upstream DNS server. The proxy uses it for upstream lookups rather than relying on the host's possibly rewritten system resolver. Upstream TLS certificates are verified against public roots and the original SNI by default. For a private upstream PKI, set `proxy.upstream_ca = "path/to/upstream-ca.pem"` to add trust roots. Generated leaf certificates are cached per SNI in memory and renewed within 24 hours of expiration. Restarting the process clears the cache.

`proxy.listen` accepts multiple addresses, such as `["0.0.0.0:443", "0.0.0.0:993"]`. Without `proxy.upstream_port`, each listener connects to the same port on the real upstream.

### Route selected domains

Add one or more `[[route]]` entries:

```toml
[[route]]
domain = "api.example.com"
upstream = "tls://192.0.2.20"
upstream_port = 9443
verify_name = "backend.example.com"

[[route]]
domain = "*.example.net"
upstream = "tcp://127.0.0.1"
upstream_port = 8080

[[route]]
domain = "lab.example.org"
upstream = "tls://192.0.2.30:443"
verify = false
```

`tls://` may be omitted. A TLS route verifies its upstream certificate against the requested SNI by default; `verify_name` selects a different certificate name. `verify = false` disables upstream certificate verification for that TLS route only and cannot be combined with `verify_name`. `tcp://` sends decrypted bytes to a plain TCP upstream and does not accept TLS verification settings.

Specify an upstream port either after the host in `upstream` or as `route.upstream_port`; specifying both is an error. If neither is set, the route uses `proxy.upstream_port`, or the listener's port if that is also unset. Exact routes take precedence over wildcard routes. `*.example.net` matches subdomains but not the apex name. If a client omits SNI, set `proxy.default_host = "example.com"` to give it an explicit default hostname.

### Provide DNS to a test device

Replace `192.0.2.10` below with an address on the proxy host that the test device can reach. Point the device's DNS setting at that address and install `example/certs/test.crt.pem` as a trusted CA on the device. Ports 53 and 443 on Linux and macOS may require elevated privileges or a separate port-forwarding setup.

```toml
[proxy]
ca_cert = "example/certs/test.crt.pem"
ca_key = "example/certs/test.key.pem"
listen = ["0.0.0.0:443"]
resolver = "1.1.1.1:53"

[dns]
listen = "0.0.0.0:53"
ip = "192.0.2.10"
all = true
```

To rewrite only selected domains and their subdomains, set `all = false` and add `domains = ["example.com", "example.net"]`. To answer AAAA queries, set `ip6` to a reachable local IPv6 address. The DNS service handles both UDP and TCP. It returns the configured address for rewritten A and AAAA queries, or an empty answer when that address family is not configured. For rewritten domains it also returns empty CNAME, DNAME, SVCB, HTTPS, and ANY answers, so those records cannot direct the client toward an alias, HTTP/3, or ECH. Other record types are forwarded to `proxy.resolver`. Do not point `proxy.resolver` at this tool's DNS listener.

### View decrypted traffic in Wireshark

Add a `[capture]` section. `capture.listen` exposes a PCAP-over-TCP stream; binding it to loopback avoids exposing decrypted traffic to the local network. `capture.output` writes PCAP to a file or a pre-created FIFO. Either option can be used alone, or both can be used together.

```toml
[capture]
listen = "127.0.0.1:57012"
# map_port = 80
# output = "/tmp/tls-mitm.pcap"
```

Each TCP viewer receives its own standard PCAP file header, followed by synthetic IP/TCP packets containing the decrypted application bytes. A regular `capture.output` file is created or truncated when the proxy starts; its permissions are restricted to the owner (0600) before plaintext is written. If the output path is an existing FIFO, the proxy waits for a reader without blocking forwarding and sends a new PCAP header when a reader reconnects. Let the previous FIFO reader disconnect before attaching a new one; a reader that takes over without a gap may miss its own header. Records can be dropped when no FIFO reader is present or an output cannot keep up. Forwarding continues.

The synthetic packets normally show the **client's actual IP and source port** and the **local IP and listening port that the client connected to**. They do not use the upstream address or PCAP listener port. `capture.map_port = 80` changes only the server port inside the PCAP; it does not change the proxy listener or upstream connection. Wireshark may decode plaintext on PCAP port 443 as TLS. Use a suitable `map_port` or Wireshark's Decode As feature. PCAP timestamps, sequence numbers, and link information represent what the proxy observed, not the original network packets.

Wireshark versions that support PCAP-over-IP can connect to the TCP stream:

```sh
wireshark -k -i TCP@127.0.0.1:57012
```

For a Wireshark version without `TCP@` input, use a FIFO directly. Create it first, enable `capture.output = "/tmp/tls-mitm.pcap"`, and then start the proxy and Wireshark:

```sh
mkfifo /tmp/tls-mitm.pcap
./target/release/tls-mitm
```

```sh
wireshark -k -i /tmp/tls-mitm.pcap
```

You may omit `capture.listen` in this setup; no separate `nc` process is needed. If `capture.output` names a regular file instead, open it in Wireshark after the test. The terminal also logs connection time, client and local addresses, SNI, the effective hostname (including a configured default), selected upstream, and closure details. A client that closes without a TLS `close_notify` does not produce a separate error for that condition.

The PCAP-over-IP format follows [PolarProxy](https://www.netresec.com/?month=2022-05&page=Blog&post=Real-time-PCAP-over-IP-in-Wireshark). See the [Wireshark pipe documentation](https://wiki.wireshark.org/CaptureSetup/Pipes) for capture-input details.

## Scope and handling

The TLS proxy handles **TCP/TLS** sent to its configured listening ports. DNS rewriting alone does not redirect ports: plain HTTP on port 80, other TCP ports without a listener, and UDP/QUIC will not reach the TLS proxy. Devices using DoH or DoT will not query this ordinary DNS service. Certificate pinning, ECH, DNSSEC validation, and mutual TLS may also prevent interception.

Upstream TLS verification stays enabled by default. Use `proxy.upstream_ca` for private upstream roots; reserve `route.verify = false` for a controlled test route. Protect the test CA private key, decrypted PCAP, and DNS and proxy listener addresses according to the test environment's access rules.

## Local validation

The test suite uses loopback services and local fixtures; it does not contact the public network. Run these checks from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --offline --all-targets --all-features -- -D warnings
cargo test --offline
cargo build --release --offline
```

The tests cover TLS proxy routes, bidirectional forwarding, PCAP output, certificate behavior, and UDP/TCP DNS rewriting. These local checks do not establish behavior on a real device or across a production network.

GitHub Actions runs formatting, Clippy, tests, a release build, and a binary startup check on Linux and macOS. The workflow caches the pinned Rust toolchain and Cargo dependencies and build artifacts for each runner platform.

## License

This project is licensed under the [MIT License](LICENSE).
