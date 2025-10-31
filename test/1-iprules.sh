# WARNING: very heavy. Use only on test VM and measure impact.

# allow lo & ssh first (as above)
sudo iptables -I INPUT 1 -i lo -j ACCEPT
sudo iptables -I INPUT 2 -p tcp --dport 22 -j ACCEPT

# send all incoming, forwarded and outgoing packets to NFQUEUE
sudo iptables -I INPUT 3 -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT 3 -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD 1 -j NFQUEUE --queue-num 0


# New

# Whitelist localhost + SSH first
sudo iptables -I INPUT 1 -i lo -j ACCEPT
sudo iptables -I OUTPUT 1 -o lo -j ACCEPT
sudo iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
sudo iptables -I OUTPUT 1 -p tcp --sport 22 -j ACCEPT

# Divide ports into ranges for each queue
sudo iptables -I INPUT 2 -p tcp --dport 1:16383   -j NFQUEUE --queue-num 0
sudo iptables -I INPUT 3 -p tcp --dport 16384:32767 -j NFQUEUE --queue-num 1
sudo iptables -I INPUT 4 -p tcp --dport 32768:49151 -j NFQUEUE --queue-num 2
sudo iptables -I INPUT 5 -p tcp --dport 49152:65535 -j NFQUEUE --queue-num 3

# Alternative approach:
# Needs iptables-mod-nfqueue and kernel support
sudo iptables -I INPUT 2 -p tcp -j NFQUEUE --queue-balance 0:3
