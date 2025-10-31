sudo snort --daq nfq --daq-var queue=0 --daq-mode inline -Q \
  -c /etc/snort/snort.conf -A console -l $SNORT_LOG_DIR
