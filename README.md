# QUIC CID Rotation with Policy-Based CLM (Python, aioquic)

This project is a **QUIC Connection ID (CID) rotation prototype** built with **aioquic**. It demonstrates:

- QUIC handshake and bidirectional **STREAM** echo
- **Explicit connection close** (`CONNECTION_CLOSE`)
- **Connection ID (CID) rotation** on both endpoints for privacy experiments
- **Baseline vs. CLM policy mode**
- **Time-based CID rotation**
- **Jittered CID lifetime**
- **Volume-based CID rotation**
- **Path-change-triggered CID rotation**
- **Grace-period-based CID retirement**
- TLS secrets logging (for **Wireshark** decryption)
- `.qlog` traces (for visualization in **qvis**)
- Structured JSONL rotation logs for analysis

> Why rotate CIDs? CID rotation reduces long-lived identifier exposure and helps make QUIC flows harder to link over time.

---

## Milestone 4 Features

This version matches the **Milestone 4** implementation and supports:

- `baseline` mode: no custom CLM-triggered rotation
- `clm` mode: policy-driven CID rotation enabled
- time-based rotation with jitter:

  ```text
  T_eff = T * (1 + delta), delta in [-J, +J]
  ```

- path-change-triggered rotation
- volume-based rotation after a byte threshold
- grace-period-based retirement of replaced CIDs
- command-line configuration for repeatable experiments

---

## Requirements

- Python **3.9+**
- **aioquic**
- OpenSSL (to generate a self-signed certificate)
- Wireshark (optional, for packet inspection)
- qvis (optional, for qlog visualization)

Install inside a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install aioquic
```

If you use a `requirements.txt`, you can also install with:

```bash
python3 -m pip install -r requirements.txt
```

---

## Project Files

Main files:

- `server.py` — QUIC echo server with CLM support
- `client.py` — QUIC client for testing and experiments
- `cid_lifecycle.py` — CID Lifecycle Manager implementation
- `analyze.py` — rotation log analyzer

Generated files and folders:

- `qlog/` — qlog traces
- `runs/server/rotation.jsonl` — server rotation log
- `runs/client/rotation_client.jsonl` — client rotation log
- `runs/server/secrets.log` — server TLS secrets log
- `runs/client/secrets.log` — client TLS secrets log

---

## Certificates

Generate a local self-signed certificate and key once:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=localhost"
```

This creates:

- `server.crt`
- `server.key`

---

## Running the Project

### 1. Start the server

Example:

```bash
python3 server.py \
  --host 127.0.0.1 \
  --port 8000 \
  --cert server.crt \
  --key server.key \
  --alpn hq-29 \
  --cid-policy clm \
  --cid-time-interval 10 \
  --cid-jitter 0.20 \
  --cid-grace-period 3
```

Example server output:

```text
[server] listening on 127.0.0.1:8000
[server] qlog dir: qlog (written on exit)
[server] secrets log: runs/server/secrets.log
[server] rotation log: runs/server/rotation.jsonl

[server cli] commands:
  help              Show commands
  status            Show status
  connections       Show number of active connections
  rotate            Force a rotate attempt on active connections
  path-change       Simulate a validated path change on active connections
  quit / exit       Stop server

[server cli] >
```

### 2. Start the client

Example:

```bash
python3 client.py \
  --host 127.0.0.1 \
  --port 8000 \
  --duration 30 \
  --alpn hq-29 \
  --cid-policy clm \
  --cid-time-interval 10 \
  --cid-jitter 0.20 \
  --cid-grace-period 3
```

Example client output:

```text
[client] connected to 127.0.0.1:8000
[client] qlog saved: qlog/client_XXXXXXXXXX.qlog.json
[client] rotation log: runs/client/rotation_client.jsonl
[client] secrets log: runs/client/secrets.log
```

The client keeps the QUIC connection open for the configured duration so that timed, volume-based, or path-change-triggered rotation events can occur during the session.

---

## Policy Modes

### Baseline mode

In baseline mode, the custom CID Lifecycle Manager does **not** perform policy-driven rotation.

Example:

```bash
python3 server.py --host 127.0.0.1 --port 8000 --cid-policy baseline
python3 client.py --host 127.0.0.1 --port 8000 --duration 20 --cid-policy baseline
```

Expected behavior:

- handshake works normally
- stream echo works normally
- no timer-based, volume-based, or path-change CLM rotations
- useful as the control case for experiments

> Note: Wireshark may still show different CID values in opposite directions because the client and server each use their own connection IDs. That does **not** mean periodic rotation is happening.

### CLM mode

In CLM mode, the CID Lifecycle Manager is active and may rotate CIDs for the following reasons:

- `timer`
- `volume`
- `path_change`
- `manual`

---

## Milestone 4 Test Scenarios

### 1. Baseline run

Server:

```bash
python3 server.py \
  --host 127.0.0.1 \
  --port 8000 \
  --cid-policy baseline
```

Client:

```bash
python3 client.py \
  --host 127.0.0.1 \
  --port 8000 \
  --duration 20 \
  --cid-policy baseline
```

Purpose:

- confirm stable connection with no CLM-triggered rotations

### 2. Time-based rotation with jitter

Server:

```bash
python3 server.py \
  --host 127.0.0.1 \
  --port 8000 \
  --cid-policy clm \
  --cid-time-interval 10 \
  --cid-jitter 0.20 \
  --cid-grace-period 3
```

Client:

```bash
python3 client.py \
  --host 127.0.0.1 \
  --port 8000 \
  --duration 30 \
  --cid-policy clm \
  --cid-time-interval 10 \
  --cid-jitter 0.20 \
  --cid-grace-period 3
```

Purpose:

- test time-based rotation
- verify that rotation deadlines vary around the base interval

With:

- `T = 10`
- `J = 0.20`

The effective lifetime will vary roughly between:

- `8s`
- `12s`

### 3. Volume-based rotation

Server:

```bash
python3 server.py \
  --host 127.0.0.1 \
  --port 8000 \
  --cid-policy clm \
  --cid-byte-threshold 300 \
  --cid-grace-period 3
```

Client:

```bash
python3 client.py \
  --host 127.0.0.1 \
  --port 8000 \
  --duration 20 \
  --send-interval 0.5 \
  --payload-size 200 \
  --cid-policy clm \
  --cid-byte-threshold 300 \
  --cid-grace-period 3
```

Purpose:

- trigger rotation based on traffic volume instead of elapsed time

Expected behavior:

- rotation log shows `reason = "volume"`

### 4. Path-change-triggered rotation

Because real path migration is difficult to reproduce on localhost, this project includes a controlled path-change trigger.

Server:

```bash
python3 server.py \
  --host 127.0.0.1 \
  --port 8000 \
  --cid-policy clm \
  --cid-time-interval 60
```

Client:

```bash
python3 client.py \
  --host 127.0.0.1 \
  --port 8000 \
  --duration 20 \
  --cid-policy clm \
  --simulate-path-change-after 5
```

Purpose:

- test the path-change trigger through a controlled event

Expected behavior:

- rotation log shows `reason = "path_change"`

You can also trigger a server-side simulated path change while the connection is active by typing this in the server CLI:

```text
path-change
```

### 5. Manual rotation

While the server is running, type:

```text
rotate
```

Expected behavior:

- a rotation attempt is logged with `reason = "manual"`

---

## Server CLI Commands

When the server is running, available commands are:

- `help` — show command list
- `status` — show current status and policy parameters
- `connections` — show number of active connections
- `rotate` — force a manual rotation attempt on active connections
- `path-change` — simulate a validated path-change trigger
- `quit` / `exit` — stop the server

---

## Inspecting Results

### Rotation logs

Analyze rotation logs with:

```bash
python3 analyze.py --rotation-log runs/server/rotation.jsonl
python3 analyze.py --rotation-log runs/client/rotation_client.jsonl
```

Typical events include:

- `clm_initialized`
- `deadline_scheduled`
- `rotate_ok`
- `rotate_failed`
- `rotate_skipped`
- `retire_connection_id_emitted`
- `retire_connection_id_failed`

Typical reasons include:

- `timer`
- `volume`
- `path_change`
- `manual`

### qlog traces

qlog files are written under `qlog/` and can be inspected in qvis.

### TLS secrets logs

Secrets logs are written to:

- `runs/server/secrets.log`
- `runs/client/secrets.log`

These can be used in Wireshark to decrypt QUIC traffic.

---

## Inspect with Wireshark

1. Open Wireshark and capture **loopback** (`lo0` on macOS / `lo` on Linux) or your NIC.
2. Use the display filter:

   ```text
   udp.port == 8000 && quic
   ```

3. Go to **Preferences → Protocols → TLS** and set **(Pre)-Master-Secret log filename** to the absolute path of the relevant secrets log file, for example:

   ```text
   /absolute/path/to/runs/client/secrets.log
   ```

   or

   ```text
   /absolute/path/to/runs/server/secrets.log
   ```

4. Add **Destination Connection ID (DCID)** as a column:
   - click a QUIC packet
   - expand **QUIC** → **Header**
   - right-click **Destination Connection ID**
   - choose **Apply as Column**

### Important note about baseline captures

Even in baseline mode, Wireshark may show more than one CID value. That is normal because:

- the client has its own CID
- the server has its own CID

That only becomes evidence of rotation if the CID used by the **same sender** changes over time during the same connection.

---

## Output Files

Your run will typically produce artifacts like these:

### Rotation logs

- `runs/server/rotation.jsonl`
- `runs/client/rotation_client.jsonl`

### TLS secrets logs

- `runs/server/secrets.log`
- `runs/client/secrets.log`

### qlog traces

- `qlog/server_<timestamp>.qlog.json`
- `qlog/client_<timestamp>.qlog.json`

---

## Program Options

### Server options

- `--host` — bind address, default `0.0.0.0`
- `--port` — server port, default `4433`
- `--cert` — server certificate path
- `--key` — server private key path
- `--qlog-dir` — qlog output directory
- `--secrets-log` — TLS secrets log file path
- `--rotation-log` — rotation log file path
- `--alpn` — ALPN string, default `hq-29`
- `--cid-policy` — `baseline` or `clm`
- `--cid-time-interval` — base interval for time-driven rotation
- `--cid-jitter` — jitter fraction `J`
- `--cid-byte-threshold` — byte threshold for volume-based rotation
- `--cid-grace-period` — grace period before retiring the old CID
- `--cid-min-gap` — minimum gap between rotations
- `--cid-random-seed` — optional seed for reproducible jitter behavior

### Client options

- `--host` — server host, default `127.0.0.1`
- `--port` — server port, default `4433`
- `--duration` — how long to keep the connection alive
- `--send-interval` — interval between client messages
- `--payload-size` — optional payload padding size
- `--qlog-dir` — qlog output directory
- `--runs-dir` — directory for client logs
- `--secrets-log` — TLS secrets log file path
- `--alpn` — ALPN string, default `hq-29`
- `--cid-policy` — `baseline` or `clm`
- `--cid-time-interval` — base interval for time-driven rotation
- `--cid-jitter` — jitter fraction `J`
- `--cid-byte-threshold` — byte threshold for volume-based rotation
- `--cid-grace-period` — grace period before retiring the old CID
- `--cid-min-gap` — minimum gap between rotations
- `--cid-random-seed` — optional seed for reproducible jitter behavior
- `--simulate-path-change-after` — trigger a controlled path-change event after N seconds

---

## Troubleshooting

### Client cannot connect / ALPN mismatch

If the client cannot connect and the server reports no common ALPN protocol, make sure both client and server use the same ALPN value, for example:

```bash
--alpn hq-29
```

### Wireshark only shows “Protected Payload”

This is normal unless you configure the TLS secrets log correctly in Wireshark.

### Rotation logs show `rotate_failed`

This can happen if:

- there is no available spare CID to switch to
- the current aioquic version exposes different internal CID structures
- the rotation path depends on internal APIs that are unavailable in your environment

Check both client and server rotation logs to understand what failed and why.

### Path-change testing on localhost

The path-change trigger can be validated at the implementation level with the simulated trigger, but localhost testing does not fully reproduce real network migration across interfaces.

### Grace-period retirement behavior

The grace-period mechanism relies on aioquic internals because the public `change_connection_id()` API retires the previous CID immediately. If internals differ across aioquic versions, retirement behavior may vary.

---

## Summary

This project now supports a **Milestone 4 policy-based evaluation framework** for QUIC CID rotation. It can compare baseline and CLM-driven behavior and test time, jitter, volume, and path-change triggers while collecting logs, qlogs, and TLS secrets for analysis.


