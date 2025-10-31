sudo apt update
sudo apt install snort zeek iptables -y

# define two dummy ports
PORT1=44444
PORT2=55555

# define unified log directory
LOG_DIR=/home/night_fury_44/Desktop/Programs/FYP/logs
SNORT_LOG_DIR=$LOG_DIR/snort_alerts
ZEEK_LOG_DIR=$LOG_DIR/zeek_logs

sudo mkdir -p $SNORT_LOG_DIR $ZEEK_LOG_DIR
echo "Using Snort logs at: $SNORT_LOG_DIR"
echo "Using Zeek logs at:  $ZEEK_LOG_DIR"