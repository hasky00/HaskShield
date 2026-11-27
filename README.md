# HaskShield

A Nostr-native shield that sits in front of a relay and keeps spam and floods out, without breaking any client.

Status: early, version 0.1. Everything described under "What it checks" is built and covered by tests against a stand-in relay. It has not yet run in front of a live relay. Treat it as something to try on a test relay first.

## Why

Open relays are getting hit from two directions at once:

1. **Connection floods.** Huge numbers of IPs open websockets and hammer the relay with requests until it stops answering.
2. **Event spam.** Junk notes are written faster than any operator can clean them up.

Ordinary bot protection (browser challenges, captchas) does not work here. Nostr clients such as Damus, Primal and Amethyst cannot solve a browser challenge, so that kind of shield locks out real users together with the bots.

HaskShield only uses defences the Nostr protocol already supports, so every client keeps working unchanged.

## How it works

```
client (Damus, Primal, Amethyst, ...)
        |
        v
   HaskShield        <- decides who gets through
        |
        v
  relay (strfry or any other)
```

HaskShield is a websocket proxy. Clients connect to it exactly as they would to the relay. The relay behind it needs no changes.

## What it checks

Checks run cheapest first, so junk is turned away before it costs anything.

| Layer | What it checks |
|---|---|
| 1. Connection | Open connections per IP, new connections per IP per minute, handshakes that stall, blocked IPs |
| 2. Message | Message rate per IP, message size, open subscriptions per connection, filters per request, anything that is not a Nostr message |
| 3. Event | Event id and signature, blocked keys, events per IP per minute, events per key per minute |
| 4. Proof of work | NIP-13 difficulty, always or only while the relay is under pressure |

The relay never sees a message that failed a check. It also never has to verify a signature on a forged event, because HaskShield already refused it.

IPv6 clients are counted per /64 network, because one attacker normally controls a whole /64.

Plain HTTP requests, including the relay information document (NIP-11), are passed through to the relay.

The relay is told each client's real address in the `X-Forwarded-For` and `X-Real-IP` headers, so its own logs and limits keep working. For strfry, set `realIpHeader = "x-real-ip"`.

### What a client sees

| Situation | Reply |
|---|---|
| Too many connections | HTTP 429, connection refused |
| Too many messages | `["OK", id, false, "rate-limited: slow down"]` for an event, `["CLOSED", sub, "rate-limited: slow down"]` for a request. A client that keeps going is disconnected |
| Forged or broken event | `["OK", id, false, "invalid: bad event id or signature"]` |
| An address posting too fast | `["OK", id, false, "rate-limited: too many events from your address"]` |
| A key posting too fast | `["OK", id, false, "rate-limited: this key is posting too fast"]` |
| Proof of work missing | `["OK", id, false, "pow: difficulty 16 required"]` |
| Too many subscriptions | `["CLOSED", sub, "rate-limited: too many open subscriptions"]` |
| Message too large | Connection closed |

These are the standard NIP-01 reply forms, so clients show them the same way they show a relay's own replies.

### Why the key limit is counted per address

Nostr events are signed, and anyone can resend an event somebody else signed. If the limit were per key alone, an attacker could replay a person's old notes until that person's key was over the limit, and so stop them posting. Counting each key per address means a replay only uses up the attacker's own allowance.

Keys are free to make, so the limit that stops a spammer is the one per address. The per-key limit is there for the single client that misbehaves.

### Pressure mode

HaskShield measures two things every second: how many connections are open in total, and how many events arrive. When either passes its threshold, pressure mode switches on, and it stays on until a full minute has passed below both.

While pressure mode is on, events need the proof of work set in `HASKSHIELD_PRESSURE_POW`. Reading is not affected, and keys on the allow list post as normal.

This is off by default (`HASKSHIELD_PRESSURE_POW=0`), because it is a real trade-off: many clients do not mine proof of work on their own, so their users cannot post until the pressure passes. Turn it on if you would rather have the relay stay readable through an attack than accept every write.

## Run it

With Rust installed:

```
HASKSHIELD_UPSTREAM=ws://127.0.0.1:7777 cargo run --release
```

HaskShield then listens on port 7778. Point your reverse proxy at it instead of at the relay.

With Docker, see `docker-compose.example.yml`. The `Dockerfile` in this repository has not been build-tested yet.

Behind Caddy, the relay's site block becomes:

```
relay.example.com {
    reverse_proxy haskshield:7778
}
```

and HaskShield needs `HASKSHIELD_TRUST_PROXY=1`, so it counts the client's address and not Caddy's.

## Settings

All settings are environment variables. A value that cannot be read stops HaskShield at start, with a message saying which one.

| Setting | Default | Meaning |
|---|---|---|
| `HASKSHIELD_LISTEN` | `0.0.0.0:7778` | Address HaskShield listens on |
| `HASKSHIELD_UPSTREAM` | `ws://127.0.0.1:7777` | The relay behind it |
| `HASKSHIELD_TRUST_PROXY` | `0` | Set to `1` only behind a reverse proxy, to read the client IP from `X-Forwarded-For`. Never set it when clients can reach HaskShield directly, or they can fake their address |
| `HASKSHIELD_MAX_CONN_PER_IP` | `20` | Open connections one IP may hold |
| `HASKSHIELD_MAX_NEW_CONN_PER_MIN` | `60` | New connections one IP may open per minute |
| `HASKSHIELD_MSGS_PER_SEC` | `20` | Messages per second per IP, with bursts of five times this |
| `HASKSHIELD_MAX_MESSAGE_BYTES` | `131072` | Largest single message from a client |
| `HASKSHIELD_MAX_SUBS_PER_CONN` | `20` | Open subscriptions per connection |
| `HASKSHIELD_MAX_FILTERS_PER_REQ` | `20` | Filters in one REQ or COUNT |
| `HASKSHIELD_VERIFY_EVENTS` | `1` | Check event id and signature. Layers 3 and 4 need this |
| `HASKSHIELD_EVENTS_PER_MIN_PER_IP` | `120` | Events one IP may publish per minute, whatever keys it uses. `0` is no limit |
| `HASKSHIELD_EVENTS_PER_MIN_PER_PUBKEY` | `30` | Events one key may publish per minute from one IP. `0` is no limit |
| `HASKSHIELD_MIN_POW` | `0` | Proof of work every event must carry |
| `HASKSHIELD_PRESSURE_POW` | `0` | Proof of work required in pressure mode |
| `HASKSHIELD_PRESSURE_CONNS` | `2000` | Open connections that start pressure mode |
| `HASKSHIELD_PRESSURE_EVENTS_PER_SEC` | `50` | Incoming events per second that start pressure mode |
| `HASKSHIELD_ALLOW_PUBKEYS` | empty | Keys (hex or npub) that skip the per-key limit and proof of work |
| `HASKSHIELD_BLOCK_PUBKEYS` | empty | Keys (hex or npub) that may not post |
| `HASKSHIELD_ALLOW_IPS` | empty | IPs that skip the connection and message limits |
| `HASKSHIELD_BLOCK_IPS` | empty | IPs that are always refused |

Lists are separated by commas or spaces.

The defaults are meant for a small public relay. If many of your users share one address (a company network, a VPN, Tor), raise the per-IP numbers.

## What it logs

One line a minute, when anything changed. The numbers here are made up:

```
haskshield: open=412 accepted=9120 refused=77301 forwarded=48211 rate_limited=1502 malformed=96 bad_signature=3110 blocked_key=0 events_limited=220 key_limited=41 pow_missing=0 subs_refused=12
```

and a line each time pressure mode switches on or off.

## Measured

On a 2-core Linux machine, holding 5000 open connections through HaskShield used about 80 MB of memory, roughly 16 KB per connection. That is one run on one machine, not a benchmark. Repeat it on yours with `cargo run --release --example load -- 5000` (see the top of `examples/load.rs`).

## What it will not do

- It cannot absorb a very large volumetric attack on a small server. It makes turning junk away cheap, which keeps the relay up far longer, but bandwidth is still bandwidth.
- It does not read or judge the meaning of posts. It limits behaviour, not opinions.
- It does not need, or ask for, any change in Nostr clients.
- It does not replace your relay's own write policy. A relay that only accepts paying members still needs that rule in the relay.

## Not built yet

- NIP-42 auth as a second pressure-mode option
- Duplicate-content detection
- An optional slower review step for unclear cases
- A metrics endpoint, in addition to the log line
- HTTP pass-through to a `wss://` relay (it needs a `ws://` upstream today)
- A config file as an alternative to environment variables

## Develop

```
cargo test
```

## Licence

MIT. See `LICENSE`.

## Made by

Hasky Labs, Copenhagen.
