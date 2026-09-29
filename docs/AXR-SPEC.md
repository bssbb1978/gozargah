# AXR Protocol Framework — Technical Specification (v2.14)

**AXR** = *Adaptive eXecuted Routing*. A client-centric framework that pairs a
**native Go client core** with the existing **gozargah Cloudflare Worker edge**
to keep a user connected through partial blackouts, SNI/IP filtering, and
national-intranet isolation — using only what a client and an edge relay may
legitimately do: TLS identity selection, transport statistics shaping, and
adaptive path selection.

---

## 1. Threat model and honest boundaries

### 1.1 What the adversary can do (assumed)

| Capability | Example | AXR counter |
| --- | --- | --- |
| SNI-based blocking | drop on `SNI: target-domain` | uTLS identity rotation + path rotation; SNI is still present (we do **not** claim SNI removal — ECH is a separate optional layer) |
| IP-based blocking | sink packets to known edge IPs | client-side clean-IP probing + live IP health cache + instant failover |
| Flow/shape heuristics | "one clean segment carries SNI", constant chunk sizes, steady inter-segment timing | ClientHello TCP segmentation, randomized post-handshake chunking, randomized gaps |
| Active probing / RST injection | reset handshakes that look suspicious | fast RST detection → arm quarantine + path rotation |
| Timeout injection (blackhole) | drop without RST | timeout detection, aggressive probe mode, backup entry ladder |

### 1.2 Hard limits (physics, stated plainly)

1. **TLS terminates at the Cloudflare edge.** Every byte of TLS-identity
   morphing and ClientHello surgery therefore lives in the **client core**.
   The Worker cannot touch the ClientHello and does not try.
2. **No deep payload inspection anywhere.** Neither the client core nor the
   Worker inspects application payloads. The client knows only its *own*
   connection outcomes (ok / RTT / error class); the Worker knows aggregate
   health statistics. There is **no DPI "detection"** in this framework —
   the regime labels describe *delivery quality*, not middlebox behavior.
3. **Total disconnection is not bypassable remotely.** If no route remains
   from the user's network to any entry point, no Worker-side or client-side
   code can create one. The system must *say so* (and it does: probe rounds
   report `no healthy candidate`) rather than loop silently.
4. **Obfuscation raises the bar; it is not a guarantee.** Statistical
   transport shaping and adaptive path selection frustrate passive and
   flow-based heuristics. An actively probing, stateful filter may still
   classify the flow. This is documented, not hidden.
5. **No UDP relay.** Consistent with the platform boundary, the client core
   is TCP-only (SOCKS5 CONNECT); UDP ASSOCIATE is rejected with
   `command not supported`.
6. **Honest naming.** Post-handshake fragmentation is **TCP-level chunking**,
   not "TLS record padding" — Go's TLS stack and utls expose no record
   padding control, and the docs/code never claim otherwise.

---

## 2. System architecture

```
┌────────────────────────────── USER DEVICE ──────────────────────────────┐
│                                                                         │
│  SOCKS5 client ──TCP──▶ ┌──────────────────────── AXR CORE (Go) ──────┐ │
│  (browser/Hiddify/      │                                             │ │
│   sing-box/v2rayN)      │  ┌─────────┐   ┌──────────┐   ┌──────────  │ │
│                         │  │  SOCKS5 │   │   BANDIT │   │ MEASURE  │  │ │
│                         │  │  (TCP)  │◀──│  UCB1    │◀──│ state    │  │ │
│                         │  └────┬────┘   │  learner │   │ vector   │  │ │
│                         │       │        └────▲─────┘   └────┬─────  │ │
│                         │       │              │reward        │samples │
│                         │  ┌────▼──────────────┴──────────────▼─────┐  │ │
│                         │  │              ROUTER / PUMPER           │  │ │
│                         │  │  arm select → candidate walk → tunnel  │  │ │
│                         │  └────┬───────────────────────────────┬───┘  │ │
│                         │       │                               │      │ │
│                         │  ┌────▼──────────┐            ┌───────▼────┐  │ │
│                         │  │  SURGERY      │            │ FAILOVER   │  │ │
│                         │  │ SplitConn     │            │ matrix +   │  │ │
│                         │  │ ChunkConn     │            │ IP health  │  │ │
│                         │  └────┬──────────            └───────┬────┘  │ │
│                         │       │                               │      │ │
│                         │  ┌────▼───────────────────────────────▼────┐  │ │
│                         │  │        VLESS-WS TUNNEL (vlessws)        │  │ │
│                         │  │  header + 0-RTT early data + RFC6455    │  │ │
│                         │  └───────────────────┬─────────────────────┘  │ │
└─────────────────────────┼──────────────────────┼────────────────────────┘
                          │                      │
        TCP (surgery applied)                   │ TLS (uTLS identity: chrome/
                          │                      │  firefox/safari/randomized)
                          ▼                      ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │  ENTRY 1 (primary)          ENTRY 2 (backup)   ...   ENTRY N     │
   │  host: entry.example.com    host: backup...    host: ...         │
   │  IPs: [104.16.x, 172.6x]   IPs: [...]                         │
   │        │                      │                               │
   └──────────────────────────────┼───────────────────────────────┘
            │  any host/IP resolves via CNAME to the SAME worker
            ▼
   ┌───────────────────────── CLOUDFLARE EDGE ──────────────────────────┐
   │                    GOZARGAH WORKER (existing)                      │
   │                                                                    │
   │  TLS terminate ──▶ WS upgrade (acceptWebSocket)                    │
   │        │          ├─ Sec-WebSocket-Protocol = b64url(VLESS hdr)    │
   │        │          │  → 0-RTT early data (≤2048 B)                 │
   │        ▼          └─ else: VLESS header in first WS binary msg     │
   │  pumpProxy ──▶ origin relay / DNS-only UDP:53 (VLESS-UDP-DNS)      │
   │        │            │  2-byte VLESS OK → stream pump               │
   │        │            ▼                                              │
   │  GET /{subPath}/{token}/axr-manifest   (NEW, 2.14)                 │
   │        │  → schema gozargah-axr-manifest/v1:                       │
   │        │    ws_path_base, fp window, regime, strategy,             │
   │        │    probe mode, measured entry health, reconnect cadence   │
   └────────────────────────────────────────────────────────────────────┘
```

### 2.1 Control loop (per connection + background)

```
                 ┌────────────────────────────────────────────┐
                 │                each SOCKS5 CONNECT         │
                 │                                            │
                 │  measure.Vector ──▶ bandit.Select(arm)     │
                 │                    │                       │
                 │              failover.FailoverOrder        │
                 │              (arm host first, health order)│
                 │                    │                       │
                 │      attempt: TCP dial → SplitConn → TLS   │
                 │               → ChunkConn → WS upgrade     │
                 │               → WaitVLESSOK → pump          │
                 │                    │                       │
                 │      reward = ok + rtt + throughput        │
                 │      error  = rst | timeout | tls | anomaly│
                 └──────────────┬─────────────────────────────┘
                                │ Observe (bandit, tracker, cache)
                 ┌──────────────▼─────────────────────────────┐
                 │  background: ProbeRound every 90 s         │
                 │  (30 s in aggressive mode)                 │
                 │    → IP health cache (atomic JSON)         │
                 │    → state machine normal ⇄ aggressive     │
                 │    → manifest refresh (path base, backups) │
                 └────────────────────────────────────────────┘
```

---

## 3. Module M1 — client-side decision core (RL engine)

**Package:** `client/internal/bandit` (pure stdlib; deterministic).

### 3.1 State vector (inputs) — `internal/measure`

Produced client-side from the client's *own* outcomes only:

| Signal | Estimator | Notes |
| --- | --- | --- |
| RTT | EWMA α=0.35 over OK samples | handshake+first-bytes latency |
| RTT jitter | EWMA α=0.30 of \|Δrtt\| | timing-instability indicator |
| RST rate | window fraction (last 40) | reset injection indicator |
| TLS timeout rate | window fraction | blackhole indicator |
| Drop step-change | lower-branch CUSUM `s = max(0, s + (P0 − 0.35) − ok)`, cap 6, alarm 2.5, re-baseline on recovery crossing | detects the *change*, not the cause |
| Anomaly code | last non-2xx/3xx HTTP / protocol code | carried through, surfaced locally |

**Regime label** (deterministic):
- `suspected_change` — baseline ≥ 0.55 success and recent-10 ≤ 0.20, with CUSUM alarm (or ≥ 50% window drop)
- `recovering` — baseline < 0.55 and recent-10 ≥ 0.75 and window drop < 25%
- `watch` — window drop ≥ 25% or RST ≥ 25% or timeout ≥ 30%
- `stable` — otherwise

### 3.2 Action space (arms)

`Arm = (host, transport, fp)` — entry domain **or** clean IP, transport
`ws` shipped (`h2`/`h3`/`grpc` reserved interface stubs, documented as not
shipped), and uTLS identity `chrome | firefox | safari | randomized`.

### 3.3 Selection (contextual UCB1)

```
mean_i   = totalReward_i / pulls_i
ucb_i    = mean_i + C · sqrt( ln(N+1) / pulls_i )      (untried: 1 + C)
total_i  = ucb_i + diversity_i + weakestHit_i
C        = 1.0, ×1.8 in suspected_change (exploration boost)
diversity= +0.05 for non-last-selected arms in suspected_change
weakestHit= −0.05 for the currently weakest transport (non-stable regime)
```

- **Quarantine:** ≥ 3 consecutive failures → exponential backoff
  60 s / 2 min / 5 min / 15 min (capped); a quarantined arm is selected only
  when no live alternative exists.
- **Reward shaping (honest, [0,1]):** success = 0.5 base + 0.5·min(tp/2MBps,1)
  − RTT penalty (≤ 0.25); any failure = 0 (quarantine does the exclusion —
  negative UCB values are deliberately avoided to keep the regret bound
  valid).
- **Auto-prune:** after ≥ 12 pulls with lifetime success ratio < 10%, the
  worst arms are pruned — always keeping ≥ 2 live arms.
- **Persistence:** JSON snapshot (atomic tmp+rename) in the cache dir.

---

## 4. Module M2 — client-side low-level surgery

**Package:** `client/internal/surgery` (pure `net.Conn` wrappers).

### 4.1 ClientHello TCP segmentation (`SplitConn`)

The first write on the fresh TCP connection — the TLS ClientHello record — is
split into **two TCP segments** at a randomized offset in **[25%, 85%]** of
the record (bias: crosses the extensions block where SNI lives), separated by
a randomized **20–120 ms** gap (configurable). Subsequent writes pass through
untouched.

Why it matters: a passive filter that keys on "single clean segment carrying
SNI" sees two segments with a variable inter-segment delta instead.

### 4.2 Post-handshake chunking (`ChunkConn`)

Every application write ≥ 512 B after the handshake is fragmented into
**randomized 512–1400 B** TCP pieces (zero-gap by default). This is
**TCP-level chunking** — varied length/timing statistics for the encrypted
stream. It is *not* TLS record padding (honest naming; no padding extension
exists in Go's TLS or utls).

### 4.3 Fingerprint permutation (uTLS)

With `-tags axr_utls`, the handshake identity is one of
`HelloChrome_Auto / HelloFirefox_Auto / HelloSafari_Auto / HelloRandomized`
(refraction-networking/utls **v1.6.7**, the single pinned external dependency).
Each arm carries its own `fp`, so the bandit can *learn* which identity the
current network tolerates. Without the tag, the OS-native Go identity is used
and `fp` is ignored (documented).

---

## 5. Module M3 — national-intranet failover

**Package:** `client/internal/failover`.

### 5.1 Endpoint matrix

`Endpoint = (host, ips[], transport, fp, priority)`. Candidate IPs =
**operator list** (`ips`) **∪** hostname. (The Worker cannot know which IPs
the *client's* network can reach — that knowledge is inherently local.)

### 5.2 Live IP health cache

Per `(host, dialAddr)`: RTT EWMA, composite score (success = 1.0 minus
slow-RTT penalty; each consecutive failure ×0.6), streaks, last error.
Persisted as **atomic JSON** (`tmp + rename`), reloaded on start. Fresh
candidates score 0.5 (below healthy, above known-dead).

### 5.3 Probe state machine

```
            ┌──────────┐  2 consecutive all-fail rounds  ┌────────────┐
            │  normal  │ ───────────────────────────────▶│ aggressive │
            └────▲─────┘                                  └──────┬─────
                 │  any success                                   │
                 └────────────────────────────────────────────────┘
```

- normal: 90 s cadence, 3 s timeout, 3 candidates/round
- aggressive: 30 s cadence, 5 s timeout, 6 candidates/round
- real traffic outcomes feed the same machine (`Observe`), so a RST storm
  during active use escalates the engine without waiting for a probe.

### 5.4 Failover order

`bandit score (endpoint) → health score (dial address)`, capped per mode,
bandit-quarantined arms sink. The router walks the selected arm's host first,
then the global order, trying candidates until one tunnel establishes —
instant, no round-trip to any control plane.

---

## 6. Module M4 — Worker edge relay

**Code:** existing gozargah Worker + the new 2.14 addition.

### 6.1 Zero-copy WS/chunked streaming (existing)

`acceptWebSocket` → `pumpProxy`: WS binary frames are pumped to the origin
relay without re-serialization of the payload (frames are forwarded as
received; VLESS header parsed once, 2-byte OK sent, then stream pump).
In-tunnel shaping (2.13 `shapeProfile`) applies bounded downlink chunking.

### 6.2 0-RTT early data (existing, used by the AXR client)

`Sec-WebSocket-Protocol` carries `b64url(VLESS header)` (≤ 2048 decoded
bytes; first byte `0` = VLESS). The header is prepended to the buffered
header read, so the client's first application bytes ride the TLS handshake —
no extra round trip after upgrade.

### 6.3 Multi-domain routing (existing)

Any entry host CNAMEs to the same Worker; routing is per-host settings with
backup entry ladder and 6 h path rotation (`rotatedPathBase`).

### 6.4 AXR machine feed (NEW)

```
GET /{subPath}/{token}/axr-manifest
→ 200 application/json, schema "gozargah-axr-manifest/v1"
```

Payload (all aggregate, no user payload data):
- `ws_path_base` + `path_rotation_minutes` (rotated path bootstrap)
- `fingerprint`: current window identity + neutral set
- `traffic_shape.mode`, `regime`, `strategy`, `probe_mode`
- `network_state`, measured `entries[]` (primary + backup ladder with latency)
- `reconnect`: strategy, probe interval (30 s in recovery), backoff ladder,
  `on_route_reopen: immediate_resume`
- `honest_limit` (explicit no-DPI-detection / no-total-bypass statement)

Authenticated by the same subscription bearer token; unknown token falls
through to the stealth landing (no user enumeration).

---

## 7. Wire compatibility

The Go VLESS header is **byte-compatible** with `src/protocols/vless.ts`:

```
[ver=0x00][uuid:16][optLen=0x00][cmd:1 (0x01 TCP | 0x02 UDP)][port:2 BE]
[atyp:1 (1=IPv4, 2=domain, 3=IPv6)][addr]
```

Success response: `[0x00, 0x00]` (2 bytes). atyp-2 domain = `len:1 + bytes`.

---

## 8. Security notes

- Client cert validation is against the **entry hostname** even when dialing
  an explicit clean IP (`ServerName` = host); `SkipCert` exists but is
  strongly discouraged and off by default.
- The manifest is fetched over HTTPS and size-limited (1 MB) at decode.
- Bandit/routing caches are written with mode 0600 inside a 0700 cache dir.
- No secrets in logs; the verbose score table contains hosts only.
- The single external dependency (`refraction-networking/utls v1.6.7`) is
  pinned in `go.mod` and used **only** behind the `axr_utls` build tag — the
  default build is 100% Go stdlib.
