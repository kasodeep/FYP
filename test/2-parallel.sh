sudo mkdir -p /var/log/ids_project/snort/q{0,1,2,3}

# Start 4 Snort workers in parallel
sudo snort --daq nfq --daq-var queue=0 --daq-mode inline -Q \
  -c /etc/snort/snort.conf -A fast -l /var/log/ids_project/snort/q0 &

sudo snort --daq nfq --daq-var queue=1 --daq-mode inline -Q \
  -c /etc/snort/snort.conf -A fast -l /var/log/ids_project/snort/q1 &

sudo snort --daq nfq --daq-var queue=2 --daq-mode inline -Q \
  -c /etc/snort/snort.conf -A fast -l /var/log/ids_project/snort/q2 &

sudo snort --daq nfq --daq-var queue=3 --daq-mode inline -Q \
  -c /etc/snort/snort.conf -A fast -l /var/log/ids_project/snort/q3 &
