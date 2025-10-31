sudo mkdir -p /tmp/ids_pipeline_backup
sudo iptables-save > /tmp/ids_pipeline_backup/iptables.before.$(date +%s).txt
