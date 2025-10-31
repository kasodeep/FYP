# Create veth pair for Snort bridge
sudo ip link add name snort_in type veth peer name snort_out

# Bring them up
sudo ip link set snort_in up
sudo ip link set snort_out up

# Create a Linux bridge
sudo ip link add name br0 type bridge
sudo ip link set br0 up

# Add your Wi-Fi NIC to bridge (replace wlp2s0 with your interface)
sudo ip link set wlp2s0 master br0

# Add snort_in to the bridge
sudo ip link set snort_in master br0


# Get your current IP info (note subnet!)
ip addr show wlp2s0

# Example move (replace 192.168.1.50/24 with your actual)
sudo ip addr flush dev wlp2s0
sudo ip addr add 192.168.1.50/24 dev br0
sudo ip route add default via 192.168.1.1

sudo snort --daq afpacket -Q \
  --daq-var buffer_size_mb=512 \
  --daq-var fanout_type=hash \
  --daq-var fanout_id=1 \
  -i snort_in:snort_out \
  -c /etc/snort/snort.conf \
  -A console

sudo /opt/zeek/bin/zeek -i br0 --no-checksums \
  Log::default_writer=Log::WRITER_ASCII \
  Log::default_logdir=/home/night_fury_44/Desktop/Programs/FYP/logs/zeek_logs

# Stop Snort & Zeek
sudo pkill snort
sudo pkill zeek

# Disable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=0

# Flush iptables
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X

# Delete veth pair
sudo ip link del snort_in

# Verify cleanup
ip link show | grep snort || echo "All clean ✅"
