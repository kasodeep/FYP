Awesome 🔥
Let’s build your **Snort → Zeek hybrid IDS pipeline** properly — where:

* **Snort** runs first, inspects all packets.
* **Alerts** are logged (for your UI/dashboard).
* **Non-alerted packets** flow to **Zeek** for behavioral logging.

We’ll do it step-by-step with a clear, production-style structure and a **bash orchestration script** to start everything automatically.

---

## 🧠 Overall Design

### 🧩 Components:

| Component              | Purpose                                        | Output                                   |
| ---------------------- | ---------------------------------------------- | ---------------------------------------- |
| **Snort (IDS)**        | Signature-based detection                      | Alert log (`/var/log/snort/alert`)       |
| **NFQUEUE / IPTables** | Controls packet routing between Snort and Zeek | Decides pass/drop                        |
| **Zeek**               | Behavioral analysis of non-alerted traffic     | Rich logs (`conn.log`, `http.log`, etc.) |

---

## 📁 Folder Structure (Recommended)

```
hybrid-ids/
│
├── config/
│   ├── snort.conf
│   ├── zeek.policy
│   └── zeek_config.sh
│
├── logs/
│   ├── snort_alerts/
│   └── zeek_logs/
│
├── scripts/
│   ├── start_snort.sh
│   ├── start_zeek.sh
│   └── hybrid_pipeline.sh   <-- main runner
│
└── README.md
```

---

## ⚙️ Step 1: Snort Configuration

You’ll need Snort to:

* Use **NFQUEUE** for packet handling.
* Log alerts properly to a known folder.

### Example Snort Command

```bash
sudo snort -Q --daq nfq --daq-var queue=0 \
  -c /etc/snort/snort.conf \
  -l ./logs/snort_alerts \
  -A fast
```

This means:

* `-Q`: inline mode
* `--daq nfq`: uses NFQUEUE to grab packets from iptables
* Logs all alerts to `./logs/snort_alerts/alert`

---

## 🧱 Step 2: IPTables Setup

You’ll create a queue (`queue-num=0`) that Snort reads from.
Example:

```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

That way, **all packets** go to Snort first.

* If Snort detects a threat → logs it.
* Otherwise, passes packet (it goes to next stage, Zeek).

---

## 🧩 Step 3: Zeek Setup

Run Zeek to capture the **non-alerted** traffic.
If you’re using 2 interfaces (say `eth0` for input, `eth1` for output), you can simply run:

```bash
sudo zeek -i eth1 Log::default_path=./logs/zeek_logs
```

But if you’re capturing from saved `.pcap` that Snort didn’t alert on (we can automate this below), use:

```bash
sudo zeek -r ./logs/snort_alerts/non_alerted.pcap Log::default_path=./logs/zeek_logs
```

---

## 🧰 Step 4: Hybrid Pipeline Script

Here’s a **complete script** to orchestrate Snort → Zeek flow:

### `scripts/hybrid_pipeline.sh`

```bash
#!/bin/bash
# Hybrid IDS Pipeline: Snort -> Zeek

# Define paths
ROOT_DIR=$(dirname "$(realpath "$0")")/..
LOG_SNORT="$ROOT_DIR/logs/snort_alerts"
LOG_ZEEK="$ROOT_DIR/logs/zeek_logs"
INTERFACE="eth0"
QUEUE_NUM=0

echo "[+] Initializing Hybrid IDS Pipeline..."
mkdir -p "$LOG_SNORT" "$LOG_ZEEK"

# Step 1: Flush old iptables and set NFQUEUE
echo "[+] Configuring iptables..."
sudo iptables -F
sudo iptables -I FORWARD -j NFQUEUE --queue-num $QUEUE_NUM

# Step 2: Start Snort in background
echo "[+] Starting Snort..."
sudo snort -Q --daq nfq --daq-var queue=$QUEUE_NUM \
  -c /etc/snort/snort.conf \
  -l "$LOG_SNORT" \
  -A fast &
SNORT_PID=$!

sleep 3
echo "[✓] Snort running with PID $SNORT_PID"

# Step 3: Start Zeek for non-alerted traffic
echo "[+] Starting Zeek..."
sudo zeek -i "$INTERFACE" Log::default_path="$LOG_ZEEK" &
ZEEK_PID=$!

sleep 3
echo "[✓] Zeek running with PID $ZEEK_PID"

# Step 4: Monitor
echo "[+] Monitoring logs..."
echo "  Snort Alerts -> $LOG_SNORT"
echo "  Zeek Logs    -> $LOG_ZEEK"
echo "Press Ctrl+C to stop both."

# Step 5: Wait for user interrupt
trap "echo '[!] Stopping...'; sudo kill $SNORT_PID $ZEEK_PID; sudo iptables -F; exit 0" SIGINT
wait
```

✅ **What this does:**

* Creates both log folders.
* Configures iptables → sends all packets to Snort.
* Starts Snort (to detect + log alerts).
* Starts Zeek in parallel to analyze traffic.
* Cleans up everything on Ctrl+C.

---

## 🧩 Step 5: Running It

1️⃣ Give execute permissions:

```bash
chmod +x scripts/*.sh
```

2️⃣ Run the pipeline:

```bash
sudo ./scripts/hybrid_pipeline.sh
```

3️⃣ Watch logs:

```bash
tail -f logs/snort_alerts/alert
tail -f logs/zeek_logs/conn.log
```

---

## 🔮 Optional Enhancement (Next Step Ideas)

| Goal                  | Approach                                                         |
| --------------------- | ---------------------------------------------------------------- |
| UI for alerts         | Tail and parse `snort_alerts/alert` into a Flask/React dashboard |
| ML on Zeek logs       | Parse `conn.log`, `http.log`, `ssl.log` → feature engineering    |
| Packet replay testing | Use `tcpreplay` with a `.pcap` file to simulate traffic          |
| Multi-node setup      | Run Zeek on another node for scalability                         |

---

Would you like me to:

1. Add a **Python or Flask script** to visualize Snort alerts (dashboard view)?
2. Or extend this to automatically **separate Zeek logs per session/day** for ML integration?
