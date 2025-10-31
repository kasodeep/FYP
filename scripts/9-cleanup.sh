sudo pkill -f "snort --daq nfq"
sudo pkill -f zeek
BACKUP="$(ls -1t /tmp/ids_pipeline_backup/iptables.before.*.txt | head -n1)"
sudo iptables-restore < "$BACKUP"
sudo mv /etc/snort/rules/local.rules.bak /etc/snort/rules/local.rules 2>/dev/null || true
sudo iptables -F