# QUIC CID Rotation (Python, aioquic)

This project is a  **QUIC CID rotation** built with **aioquic**.  
It demonstrates:

- QUIC handshake and bidirectional **STREAM** echo
- **Explicit connection close** (`CONNECTION_CLOSE`)
- **Connection ID (CID) rotation** on both ends (privacy)
- TLS secrets logging (for **Wireshark** decryption)
- `.qlog` traces (for visualization in **qvis**)

> Why rotate CIDs? It reduces linkability of flows by periodically switching the QUIC Connection ID used on the wire.

---

## 📦 Requirements

- Python **3.9+** (tested with 3.13 on macOS)
- **aioquic ≥ 0.9.25** (needed for `change_connection_id()` API)
- OpenSSL (to generate a self-signed certificate)
- Wireshark (optional, to view decrypted QUIC)
- qvis (optional, to view `.qlog`)

Install (inside a virtualenv):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Confirm your environment:

```bash
python3 -c "import sys, aioquic, aioquic.quic.connection as c; print(sys.executable); print('aioquic', aioquic.__version__); print('has change_connection_id:', hasattr(c.QuicConnection,'change_connection_id'))"
```

`has change_connection_id: True` is required.

---

## 🔐 Certificates

Generate a local self-signed cert/key once:

```bash
openssl req -x509 -newkey rsa:2048 -nodes   -keyout server.key -out server.crt -days 365   -subj "/CN=localhost"
```

This creates `server.crt` and `server.key`.

---

## ▶️ Running

### 1) Server (CID rotation on by default)

```bash
python server.py --port 8000 --cert server.crt --key server.key --alpn hq-29 --rotate-interval 3 --jitter 1
```

### 2) Client (holds connection so you can observe rotations)

```bash
python client.py --host 127.0.0.1 --port 8000 --duration 20 --alpn hq-29 --rotate-interval 3 --jitter 1
```

### What you’ll see in the terminals

- On server:
  ```
  [server] listening on 0.0.0.0:8000
  [server] qlog dir: qlog (written on exit)
  [server] secrets log: runs/server/secrets.log
  [server] rotation log: runs/server/rotation.jsonl

  [server cli] commands:
  help            Show commands
  status          Show status
  connections     Show number of active connections
  rotate          Force a rotate attempt on active connections
  quit / exit     Stop server

  [server cli] >
  ```
  
- On client:
  ```
   [client] connected to 127.0.0.1:8000
   [client] qlog saved: qlog/client_1770616022.qlog.json
   [client] rotation log: runs/rotation_client.log
   [client] secrets log: runs/client/secrets.log
  ```
- It depends on the duration and the rotation-interval to shows the log file in the client terminal. It might also have delay.

---

## 🔍 Inspect with Wireshark (incl. seeing CID rotation)

1. Open Wireshark and capture **loopback** (`lo0` on macOS / `lo` on Linux) or your NIC.
2. Display filter:
   ```
   udp.port == 8000 && quic
   ```
3. Preferences → **Protocols → TLS** → set **(Pre)-Master-Secret log filename** to the **absolute path** of `runs/sever/secret.log`.
4. Add **Destination Connection ID (DCID)** as a column:
   - Click any QUIC packet → expand **QUIC** → **Header** → right-click **Destination Connection ID** → **Apply as Column**.

As rotation runs, the **DCID** column will change in the appropriate direction.

## 📊 Output files (where to look)

Your run will produce artifacts similar to:

- Secrets logs (Wireshark decryption)
- client: secrets.log (or whatever you pass via --secrets-log)
- server: typically under runs/server/secrets.log (depends on your server config)
- Rotation logs (CID rotation events)
- client: runs/rotation_client.log (or similar)
- server: runs/server/rotation.jsonl (or similar)
- qlog traces (if enabled)
- under a qlog/ directory (client/server qlog JSON files)

---

## ⚙️ Program options (summary)

### Server
- `--addr` *(default: 0.0.0.0)*
- `--port` *(default: 8443)*
- `--cert`, `--key` *(defaults: `server.crt`, `server.key`)*
- `--qlog-dir` *(default: `qlog`)*
- `--cid-interval` *(seconds between CID rotations; default: 10)*

### Client
- `--host` *(default: 127.0.0.1)*
- `--port` *(default: 8443)*
- `--qlog-dir` *(append secrets to `qlog/secrets.log`)*
- `--duration` *(keep connection open after echo; default: 15s)*
- `--cid-interval` *(seconds between rotations; default: 5)*

## Troubleshooting

- **Client can’t connect + server shows “No common ALPN protocols**  
-- This usually means the client and server don’t agree on the application protocol string (ALPN). Make sure both sides set the same ALPN list (for example ["hq-29"] or a consistent value used in both configs).

- **Wireshark shows QUIC but payload is “Protected Payload”**  
-- Normal unless you configured TLS secrets log in Wireshark correctly.

- **Rotation logs show rotate_ok but “found” is empty**  
-- It can mean the rotation attempt executed but there were no available/advertised CIDs to switch to at that moment, or the API used didn’t expose the peer CID set. Check both sides’ rotation logs to confirm behavior.