sudo iptables -I INPUT 1 -i lo -j ACCEPT
sudo iptables -I OUTPUT 1 -o lo -j ACCEPT
sudo iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
sudo iptables -I OUTPUT 1 -p tcp --sport 22 -j ACCEPT

# redirect dummy ports to NFQUEUE
sudo iptables -I INPUT 2 -p tcp --dport $PORT1 -j NFQUEUE --queue-num 0
sudo iptables -I INPUT 3 -p tcp --dport $PORT2 -j NFQUEUE --queue-num 0

sudo iptables -L -n --line-numbers | sed -n '1,200p'
