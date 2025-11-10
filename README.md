# QUIC Echo + CID Rotation (Python, aioquic)

This project is a minimal **QUIC echo server and client** built with [aioquic].  
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
pip install "aioquic>=0.9.25"
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
python3 server_rot_cid.py   --addr 0.0.0.0   --port 8443   --qlog-dir qlog   --cid-interval 10
```

Optional:
- `--auto-close` — server closes after echo (default: off)
- `--close-delay <sec>` — delay before auto-close if enabled

### 2) Client (holds connection so you can observe rotations)
```bash
python3 client_rot_cid.py   --host 127.0.0.1   --port 8443   --in "hello quic"   --qlog-dir qlog   --hold 15   --cid-interval 5
```

Expected client output:
```
hello quic
```

### What you’ll see in the terminals

- On each rotation you’ll see log lines like:
  ```
  [EchoClient] rotated CID -> 36aec7b557c36f9a
  [EchoServerProtocol] rotated CID -> b5237e100f4de98
  ```
- If you enabled server `--auto-close`, the client will stop rotating shortly after echo.
  To observe more rotations, **leave auto-close off** and use the client’s `--hold`.

---

## 🔍 Inspect with Wireshark (incl. seeing CID rotation)

1. Open Wireshark and capture **loopback** (`lo0` on macOS / `lo` on Linux) or your NIC.
2. Display filter:
   ```
   udp.port == 8443 && quic
   ```
3. Preferences → **Protocols → TLS** → set **(Pre)-Master-Secret log filename** to the **absolute path** of `qlog/secrets.log`.
4. Add **Destination Connection ID (DCID)** as a column:
   - Click any QUIC packet → expand **QUIC** → **Header** → right-click **Destination Connection ID** → **Apply as Column**.

### Which direction should match which log?

- The CID printed by **client logs** (its **host CID**) will show up as **DCID in packets from the *server → client***.
- The CID printed by **server logs** will show up as **DCID in packets from the *client → server***.

Use direction filters to separate flows (replace `NNNNN` with the client’s ephemeral port you see in the capture):
```
# client → server
udp.srcport == NNNNN && udp.dstport == 8443

# server → client
udp.srcport == 8443 && udp.dstport == NNNNN
```

As rotation runs, the **DCID** column will change in the appropriate direction.

### Other handy filters

- Handshake only:
  ```
  quic.packet_type == 0 || quic.packet_type == 1  # Initial/Handshake
  ```
- STREAM frames:
  ```
  quic.frame_type == 0x08
  ```
- CONNECTION_CLOSE:
  ```
  quic.frame_type == 0x1c
  ```

---

## 📊 Visualize `.qlog` with qvis

Both sides write qlogs to `qlog/`. Open https://qvis.edm.uhasselt.be and drop in the `.qlog` files to inspect timelines, frames, ACKs, etc.

---

## ⚙️ Program options (summary)

### Server
- `--addr` *(default: 0.0.0.0)*
- `--port` *(default: 8443)*
- `--cert`, `--key` *(defaults: `server.crt`, `server.key`)*
- `--qlog-dir` *(default: `qlog`)*
- `--cid-interval` *(seconds between CID rotations; default: 10)*
- `--auto-close` *(close after echo; default: off)*
- `--close-delay` *(delay before auto-close)*

### Client
- `--host` *(default: 127.0.0.1)*
- `--port` *(default: 8443)*
- `--in` *(message to echo; default: "hello quic")*
- `--qlog-dir` *(append secrets to `qlog/secrets.log`)*
- `--local-port` *(bind a local UDP port; default: 0 = ephemeral)*
- `--hold` *(keep connection open after echo; default: 15s)*
- `--cid-interval` *(seconds between rotations; default: 5)*

> Security note (demo only): the client sets `cfg.verify_mode = CERT_NONE` so self-signed `server.crt` works.  
> For real deployments, use:
> ```python
> cfg.verify_mode = ssl.CERT_REQUIRED
> cfg.load_verify_locations("server.crt")
> ```

---

## 🧰 Troubleshooting

- **`WARNING change_connection_id() not available in this aioquic quic version`**  
  You’re running an older `aioquic`. Upgrade in the same venv you use to run:
  ```bash
  pip install --upgrade "aioquic>=0.9.25"
  ```
  Re-check with the one-liner under *Requirements*.

- **Rotations stop quickly on the client**  
  The server likely closed after echo. Run the server **without** `--auto-close`, or add `--close-delay 20` to watch more rotations.

- **Wireshark CIDs don’t match my logs**  
  Check **direction** (see “Which direction should match which log?”) and make DCID a column. Remember: your log shows the CIDs **you advertise**; they appear as **the peer’s DCID**.

- **No decrypted QUIC**  
  Ensure `qlog/secrets.log` path is correct and absolute in Wireshark TLS settings. Start capture **before** running client/server.

---

Happy hacking & privacy-testing!
