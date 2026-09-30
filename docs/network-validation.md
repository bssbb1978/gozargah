# AXR multi-network validation protocol

This is a manual, real-socket validation protocol. It does not create or contain measurements. `axr validate` makes actual TCP/TLS/WebSocket/VLESS handshake attempts from the machine where the command runs and exports one JSON document per run. Unit tests and the simulated DPI fixtures are **simulations** and must never be added to measurement results.

## Probe definition and limits

A successful attempt means: TCP dial to an AXR entry candidate, TLS handshake, WebSocket upgrade, VLESS `OK`, and a Worker-side TCP connect to the chosen destination. It sends no application payload. Latency is the client-observed elapsed time through the VLESS handshake. It measures this machine's current route only.

The client transport coverage is `ws` and `ws-alt` (the alternate WebSocket path/query shape). This harness does not measure gRPC, HTTP/2, XHTTP, or an origin-engine listener. `fallback_tier` is the zero-based candidate attempt index from the local failover health/priority ordering for that run; it is not a promise that every consumer uses the same order (the live tunnel also uses its learned bandit). Network and ISP labels are typed by the operator and are not independently verified or geolocated. A live socket observation from a VPN, test endpoint, proxy, local mock, or another ISP is not an inside-Iran carrier measurement.

## Run one network sample

1. Build the current AXR binary on the test device/host, using the repository's pinned Go toolchain. Keep `axr.json` private; it contains the subscription UUID/token and must not be shared.
2. Run without a VPN, proxy, or another tunnel. Use one physical network at a time and manually label it; the program deliberately does not infer an ISP from IP/ASN.
3. Example from `client/`:

   ```sh
   go run ./cmd/axr validate \
     -config ./axr.json \
     -network mobile-data \
     -isp "operator label" \
     -destination www.cloudflare.com:443 \
     -repeats 10 \
     -timeout 12s \
     -out ./validation/mobile-operator-run1.json
   ```

   Use a separate, uniquely named output file for every run. The command also prints the same JSON to stdout. It records UTC timestamps, labels, destination, entry host, dial address, `ws`/`ws-alt`, success, latency, repeat/attempt number, and a coarse failure phase. It intentionally omits the UUID, subscription token, and raw error text.
4. Review the JSON before sharing it. Entry hostnames and dial addresses may still be sensitive. Do not share `axr.json`, terminal environment variables, account tokens, or credentials.

## Multi-ISP/mobile collection

- Collect at least 10 repeats on each of: MCI/Hamrah-e Aval mobile data, Irancell mobile data, Rightel mobile data, a fixed-line ISP, and any available Wi-Fi network. Use the actual carrier/service name shown by the SIM or contract; do not guess from IP addresses.
- Repeat each set in a second time window. Record separate JSON files rather than merging labels or overwriting earlier runs. Keep destination, binary version, config entry set, timeout, and repeat count constant where possible.
- For each run, note (outside the JSON) city/region at coarse granularity, date/time window, access type (LTE/5G/fixed/Wi-Fi), device/OS, and whether the configured entry list changed. Do not include subscriber identity, phone number, exact home address, or user credentials.
- Do not interpret a failed handshake as proof of DPI, censorship, or an international cut. Failures can result from local radio, DNS, routing, server configuration, or destination outages. A fully simulated scenario is not a real network sample.
- Summarize success rate, latency distribution, and the fallback-tier distribution per manually supplied network/ISP label only after collecting the actual JSON exports. Retain raw files and report missing/failed runs; do not substitute CI fixtures or estimates.

## Evidence status for this repository run

No probe was executed from inside Iran, and no real ISP/mobile-network result is reported here. The command's Go build/test coverage is hosted CI validation only; it is not a connectivity measurement. The tests for SNI-block, RST, throttling, partial cut, and full cut remain explicitly synthetic regression tests.
