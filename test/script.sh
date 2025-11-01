#!/bin/bash
# Snort + Zeek Inline Bridge Setup Script (Dynamic & Stable)
# Author: Night Fury & GPT-5 Assistant

set -e

# === AUTO-DETECT & CONFIGURE ===
ETH_IF=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}')
: "${ETH_IF:=enp3s0}"  # fallback if auto-detect fails

BR_IF="br0"
VETH_IN="snort_in"
VETH_OUT="snort_out"
SNORT_CONF="/etc/snort/snort.conf"
BASE_DIR="$HOME/Desktop/Programs/FYP/logs"
SNORT_LOG="$BASE_DIR/snort_logs"
ZEEK_LOG="$BASE_DIR/zeek_logs"

# Change IP & gateway to your LAN settings
BR_IP="192.168.1.50/24"
GATEWAY="192.168.1.1"

# === PREPARE DIRECTORIES ===
sudo mkdir -p "$SNORT_LOG" "$ZEEK_LOG"
sudo chown "$USER":"$USER" "$SNORT_LOG" "$ZEEK_LOG"

# === CLEANUP OLD CONFIG ===
echo "[*] Cleaning up old bridge/veth setup..."
sudo pkill snort 2>/dev/null || true
sudo pkill zeek 2>/dev/null || true
sudo ip link del $VETH_IN 2>/dev/null || true
sudo ip link del $BR_IF 2>/dev/null || true

# === CREATE VETH PAIR ===
echo "[*] Creating veth pair..."
sudo ip link add name $VETH_IN type veth peer name $VETH_OUT
sudo ip link set $VETH_IN up
sudo ip link set $VETH_OUT up

# === CREATE BRIDGE ===
echo "[*] Creating bridge $BR_IF..."
sudo ip link add name $BR_IF type bridge
sudo ip link set $BR_IF up

# === ADD INTERFACES TO BRIDGE ===
echo "[*] Adding interfaces to bridge..."
sudo ip link set $ETH_IF master $BR_IF
sudo ip link set $VETH_IN master $BR_IF

# === MOVE IP CONFIG TO BRIDGE ===
echo "[*] Moving IP config to bridge..."
CURRENT_IP=$(ip addr show $ETH_IF | grep "inet " | awk '{print $2}' || true)
if [ -n "$CURRENT_IP" ]; then
  echo "  -> Found IP $CURRENT_IP on $ETH_IF, moving it to $BR_IF"
  sudo ip addr flush dev $ETH_IF
  sudo ip addr add $CURRENT_IP dev $BR_IF
else
  echo "  -> Assigning manual IP $BR_IP to $BR_IF"
  sudo ip addr add $BR_IP dev $BR_IF
fi
sudo ip route add default via $GATEWAY || true

# === ENABLE PROMISCUOUS MODE ===
sudo ip link set $ETH_IF promisc on
sudo ip link set $VETH_IN promisc on
sudo ip link set $VETH_OUT promisc on

# === VERIFY BRIDGE ===
echo "[*] Bridge status:"
brctl show

# === START SNORT INLINE ===
echo "[*] Starting Snort inline..."
sudo snort --daq afpacket -Q \
  --daq-var buffer_size_mb=512 \
  -i $VETH_IN:$VETH_OUT \
  -c $SNORT_CONF \
  -A console \
  -l $SNORT_LOG &

sleep 3

# === START ZEEK ===
echo "[*] Starting Zeek on filtered output..."
sudo /opt/zeek/bin/zeek -i $VETH_OUT --no-checksums \
  Log::default_writer=Log::WRITER_ASCII \
  Log::default_logdir=$ZEEK_LOG &

sleep 3
echo "[+] Setup complete. All traffic is now inspected inline by Snort and logged by Zeek."
echo "    Bridge interface: $BR_IF"
echo "    Zeek interface:   $VETH_OUT"
echo "    Logs:"
echo "      Snort -> $SNORT_LOG"
echo "      Zeek  -> $ZEEK_LOG"

# === FAILSAFE ===
read -p "Press ENTER to tear down the setup and restore normal network..."
sudo pkill snort 2>/dev/null || true
sudo pkill zeek 2>/dev/null || true
sudo ip link del $BR_IF 2>/dev/null || true
sudo ip link del $VETH_IN 2>/dev/null || true
sudo ip addr flush dev $ETH_IF
sudo ip addr add $BR_IP dev $ETH_IF
sudo ip route add default via $GATEWAY || true
sudo ip link set $ETH_IF up
echo "[*] Network restored."
