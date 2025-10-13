# QUIC Echo Prototype (Python, aioquic)
- After this prototype, i will be added a CID rotation into the quic protocol, to improve it from privacy.

This project is a minimal **QUIC echo server and client** built with [aioquic](https://github.com/aiortc/aioquic).  
It demonstrates QUIC handshakes, stream data transfer, and explicit connection termination (`CONNECTION_CLOSE`).  
It also supports TLS secrets logging (for Wireshark decryption) and `.qlog` traces (for visualization in [qvis](https://qvis.edm.uhasselt.be)).

---

## 📦 Requirements
- Python 3.9+ (tested with Python 3.13 on macOS)
- [aioquic](https://pypi.org/project/aioquic/)
- OpenSSL (to generate self-signed certificates)
- Wireshark (optional, to view decrypted QUIC packets)
- [qvis](https://qvis.edm.uhasselt.be) (optional, to visualize `.qlog` traces)

---

## 🔧 Setup

Clone this repository and set up a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Generate a self-signed TLS certificate and private key:

```bash
openssl req -x509 -newkey rsa:2048 -nodes   -keyout server.key -out server.crt   -days 365 -subj "/CN=localhost"
```

This creates:
- `server.crt` (certificate)
- `server.key` (private key)

---

## ▶️ Running

### Start the server
```bash
python3 server.py --addr 0.0.0.0 --port 8443 --qlog-dir qlog
```

### Run the client
```bash
python3 client.py --host 127.0.0.1 --port 8443 --in "hello quic protocol" --qlog-dir qlog
```

Expected output on the client:
```
hello quic protocol
```

After the echo exchange, both client and server send `CONNECTION_CLOSE` frames with reason phrases (`done` / `server done`).

---

## 🔍 Inspect with Wireshark

1. Open Wireshark and capture on the **loopback interface** (`lo0` on macOS, `lo` on Linux).
2. Use a display filter:
   ```
   udp.port == 8443
   ```
3. Go to **Preferences → Protocols → TLS** and set:
   - **(Pre)-Master-Secret log filename** = `qlog/secrets.log`
4. Run the server and client again. You should now see decrypted QUIC traffic:
   - **Initial / Handshake packets** (`CRYPTO` frames)
   - **STREAM frames** with your plaintext (`hello quic protocol`)
   - **CONNECTION_CLOSE frames**

Useful filters:
- Handshake only:
  ```
  quic.packet_type == 0
  ```
- Stream data:
  ```
  quic.frame_type == 0x08
  ```
- Connection close:
  ```
  quic.frame_type == 0x1c
  ```

---

## 📊 Visualize with qvis

The server/client generate `.qlog` files in the `qlog/` directory.  
To view them:

1. Open [qvis](https://qvis.edm.uhasselt.be) in your browser.
2. Upload the `.qlog` files.
3. Inspect packet timeline, handshake details, ACKs, and connection closes.

---

## ⚠️ Notes
- For simplicity, the client disables certificate verification (`CERT_NONE`).  
  In production, replace this with:
  ```python
  cfg.verify_mode = ssl.CERT_REQUIRED
  cfg.load_verify_locations("server.crt")
  ```
- Use a high port (like 8443) to avoid conflicts with system services.
- QUIC always uses TLS 1.3 internally; even this echo app has a full TLS handshake.

