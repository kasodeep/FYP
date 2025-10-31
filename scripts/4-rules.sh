sudo mkdir -p /etc/snort/rules/backups
sudo cp /etc/snort/rules/local.rules /etc/snort/rules/backups/local.rules.bak 2>/dev/null || true

echo "drop tcp any any -> any ${PORT1} (msg:\"DUMMY_PORT1_DROP - blocked suspicious traffic\"; sid:1009001; rev:1;)" | sudo tee -a /etc/snort/rules/local.rules
echo "alert tcp any any -> any ${PORT2} (msg:\"DUMMY_PORT2_ALERT - potential probe detected\"; sid:1009002; rev:1;)" | sudo tee -a /etc/snort/rules/local.rules
