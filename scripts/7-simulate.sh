# Replace <LAPTOP_IP> with your Snort/Zeek machine IP
nmap -Pn -p $PORT1,$PORT2 <LAPTOP_IP>
# or
nc -vz <LAPTOP_IP> $PORT1
nc -vz <LAPTOP_IP> $PORT2

python3 -m http.server 33333 --bind 0.0.0.0
curl http://<LAPTOP_IP>:33333