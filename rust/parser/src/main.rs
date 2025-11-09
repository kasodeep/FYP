use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use etherparse::{InternetSlice, TransportSlice};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use pcap_file::{DataLink, pcap::PcapReader, pcap::PcapWriter};
use serde::{Deserialize, Serialize};
use serde_json::Deserializer;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, Read, BufRead, BufReader, Write},
    net::IpAddr,
    path::PathBuf,
};

/// Example Suricata EVE JSON alert:
/// {
///   "timestamp": "2025-11-07T10:00:00.000000+0000",
///   "flow_id": 123456789,
///   "pcap_cnt": 42,
///   "src_ip": "192.168.1.100",
///   "src_port": 12345,
///   "dest_ip": "10.0.0.1",
///   "dest_port": 80,
///   "proto": "TCP",
///   "alert": {
///     "signature_id": 2001234,
///     "rev": 1,
///     "gid": 1,
///     "signature": "ET MALWARE Known Malicious SSL Cert",
///     "category": "Malware"
///   }
/// }

#[derive(Parser, Debug)]
#[command(version, about = "Split pcap based on Suricata alerts")]
struct Args {
    /// Input pcap file
    #[arg(short, long)]
    input: PathBuf,

    /// Suricata EVE JSON file
    #[arg(short, long)]
    eve: PathBuf,

    /// Output clean pcap file
    #[arg(short, long)]
    clean: PathBuf,

    /// Output quarantine pcap file
    #[arg(short, long)]
    quarantine: PathBuf,

    /// Matching mode (packet or flow)
    #[arg(short, long, default_value = "packet")]
    mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IpAddress {
    String(String),
    Object { ip: String },
}

impl IpAddress {
    fn get_ip(&self) -> String {
        match self {
            IpAddress::String(s) => s.clone(),
            IpAddress::Object { ip } => ip.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Alert {
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    flow_id: Option<u64>,
    #[serde(default)]
    pcap_cnt: Option<u64>,
    #[serde(alias = "src_ip")]
    #[serde(alias = "source")]
    src_ip: IpAddress,
    #[serde(default)]
    src_port: u16,
    #[serde(alias = "dest_ip")]
    #[serde(alias = "destination")]
    dest_ip: IpAddress,
    #[serde(default)]
    dest_port: u16,
    #[serde(alias = "proto")]
    #[serde(alias = "protocol")]
    #[serde(default = "default_proto")]
    proto: String,
    alert: AlertDetails,
}

fn default_proto() -> String {
    "UNKNOWN".to_string()
}

#[derive(Debug, Deserialize)]
struct AlertDetails {
    #[serde(default)]
    signature_id: u32,
    #[serde(alias = "msg")]
    #[serde(default = "default_signature")]
    signature: String,
}

fn default_signature() -> String {
    "Unknown Alert".to_string()
}

#[derive(Debug, Serialize)]
struct FilterLog {
    packet_index: u64,
    alerts: Vec<AlertInfo>,
}

#[derive(Debug, Serialize)]
struct AlertInfo {
    signature_id: u32,
    signature: String,
    timestamp: String,
    src: String,
    dst: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct Flow {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

#[derive(Debug)]
struct PacketInfo {
    index: u64,
    ts_sec: u32,
    ts_usec: u32,
    flow: Flow,
    hash: Option<String>,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Starting pcap processing with {:?}", args);

    // Step 1: Build packet index and collect malicious packet information
    let mut packet_index = Vec::new();
    let mut malicious_packets = HashSet::new();
    let mut malicious_flows = HashSet::new();
    let mut filter_log = Vec::new();

    // First pass: Index packets
    info!("Indexing input pcap...");
    index_pcap(&args.input, &mut packet_index)?;

    // Process EVE JSON alerts
    info!("Processing Suricata alerts...");
    process_alerts(
        &args.eve,
        &packet_index,
        &mut malicious_packets,
        &mut malicious_flows,
        &mut filter_log,
        &args.mode,
    )?;

    // Second pass: Split pcap into clean and quarantine files
    info!("Splitting pcap into clean and quarantine files...");
    split_pcap(
        &args.input,
        &args.clean,
        &args.quarantine,
        &malicious_packets,
        &malicious_flows,
        &args.mode,
    )?;

    // Write filter log
    let log_path = args.quarantine.with_extension("json");
    write_filter_log(&log_path, filter_log)?;

    Ok(())
}

fn index_pcap(input_path: &PathBuf, packet_index: &mut Vec<PacketInfo>) -> Result<()> {
    let file = File::open(input_path).context("Failed to open input pcap")?;
    let mut pcap_reader = PcapReader::new(file)?;
    let mut packet_number = 1u64;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );

    while let Some(packet) = pcap_reader.next_packet() {
        let packet = packet?;

        if let Some(flow) = parse_packet_flow(&packet.data) {
            packet_index.push(PacketInfo {
                index: packet_number,
                ts_sec: packet.timestamp.as_secs() as u32,
                ts_usec: packet.timestamp.subsec_micros(),
                flow,
                hash: Some(calculate_packet_hash(
                    &packet.data[..64.min(packet.data.len())],
                )),
            });
        }

        if packet_number % 10000 == 0 {
            pb.set_message(format!("Indexed {} packets", packet_number));
        }
        packet_number += 1;
    }

    pb.finish_with_message(format!("Indexed {} packets total", packet_number - 1));
    Ok(())
}

fn parse_packet_flow(packet_data: &[u8]) -> Option<Flow> {
    match etherparse::SlicedPacket::from_ethernet(packet_data) {
        Ok(packet) => {
            let ip_slice = packet.ip?;
            let (src_ip, dst_ip, protocol) = match ip_slice {
                InternetSlice::Ipv4(header, _extensions) => (
                    IpAddr::V4(header.source_addr()),
                    IpAddr::V4(header.destination_addr()),
                    header.protocol(),
                ),
                InternetSlice::Ipv6(header, _extensions) => (
                    IpAddr::V6(header.source_addr()),
                    IpAddr::V6(header.destination_addr()),
                    header.next_header(),
                ),
            };

            let (src_port, dst_port) = match packet.transport? {
                TransportSlice::Tcp(header) => (header.source_port(), header.destination_port()),
                TransportSlice::Udp(header) => (header.source_port(), header.destination_port()),
                _ => return None,
            };

            Some(Flow {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            })
        }
        Err(_) => None,
    }
}

fn calculate_packet_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(&hasher.finalize()[..8]) // Use first 8 bytes only
}

fn process_alerts(
    eve_path: &PathBuf,
    packet_index: &[PacketInfo],
    malicious_packets: &mut HashSet<u64>,
    malicious_flows: &mut HashSet<Flow>,
    filter_log: &mut Vec<FilterLog>,
    mode: &str,
) -> Result<()> {
    let file = File::open(eve_path).context("Failed to open EVE JSON file")?;
    let mut reader = BufReader::new(file);

    // Try to parse as a JSON array first
    let mut content = String::new();
    reader.read_to_string(&mut content)?;

    let alerts: Vec<Alert> = match serde_json::from_str(&content) {
        Ok(alerts) => {
            info!("Processing EVE JSON in array format");
            alerts
        }
        Err(_) => {
            info!("Processing EVE JSON in line-delimited format");
            // If array parsing fails, try line-delimited format
            content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .filter_map(|line| match serde_json::from_str::<Alert>(line) {
                    Ok(alert) => Some(alert),
                    Err(e) => {
                        error!("Failed to parse line: {}", e);
                        error!("Problematic line content: {}", line);
                        None
                    }
                })
                .collect()
        }
    };

    let pb = ProgressBar::new(alerts.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} alerts processed ({msg})")
            .unwrap()
    );
    let pb = ProgressBar::new_spinner();

    for alert in alerts {
        pb.inc(1);
        if pb.position() % 1000 == 0 {
            pb.set_message(format!(
                "Found {} malicious items",
                malicious_packets.len() + malicious_flows.len()
            ));
        }

        // Direct packet index mapping
        if let Some(pcap_cnt) = alert.pcap_cnt {
            malicious_packets.insert(pcap_cnt);
            record_alert(filter_log, pcap_cnt, &alert);
            continue;
        }

        // Flow-based mapping
        if mode == "flow" {
            if let (Ok(src_ip), Ok(dst_ip)) = (
                alert.src_ip.get_ip().parse(),
                alert.dest_ip.get_ip().parse(),
            ) {
                let flow = Flow {
                    src_ip,
                    dst_ip,
                    src_port: alert.src_port,
                    dst_port: alert.dest_port,
                    protocol: protocol_str_to_num(&alert.proto),
                };
                malicious_flows.insert(flow);
            }
            continue;
        }

        // Time-based packet matching
        if let Ok(alert_time) = DateTime::parse_from_rfc3339(&alert.timestamp) {
            match_packets_by_time(
                packet_index,
                malicious_packets,
                filter_log,
                &alert,
                alert_time.timestamp() as u32,
            );
        }
    }

    pb.finish();
    Ok(())
}

fn protocol_str_to_num(proto: &str) -> u8 {
    match proto.to_uppercase().as_str() {
        "TCP" => 6,
        "UDP" => 17,
        "ICMP" => 1,
        _ => 0,
    }
}

fn match_packets_by_time(
    packet_index: &[PacketInfo],
    malicious_packets: &mut HashSet<u64>,
    filter_log: &mut Vec<FilterLog>,
    alert: &Alert,
    alert_ts: u32,
) {
    const TIME_WINDOW: u32 = 500; // milliseconds

    for packet in packet_index {
        if (packet.ts_sec as i64 - alert_ts as i64).abs() <= 1 {
            // Check if packet is within +/- 500ms
            let packet_ms = packet.ts_sec * 1000 + packet.ts_usec / 1000;
            let alert_ms = alert_ts * 1000;

            if (packet_ms as i64 - alert_ms as i64).abs() <= TIME_WINDOW as i64 {
                malicious_packets.insert(packet.index);
                record_alert(filter_log, packet.index, alert);
            }
        }
    }
}

fn record_alert(filter_log: &mut Vec<FilterLog>, packet_index: u64, alert: &Alert) {
    let alert_info = AlertInfo {
        signature_id: alert.alert.signature_id,
        signature: alert.alert.signature.clone(),
        timestamp: alert.timestamp.clone(),
        src: format!("{}:{}", alert.src_ip.get_ip(), alert.src_port),
        dst: format!("{}:{}", alert.dest_ip.get_ip(), alert.dest_port),
    };

    if let Some(existing) = filter_log
        .iter_mut()
        .find(|l| l.packet_index == packet_index)
    {
        existing.alerts.push(alert_info);
    } else {
        filter_log.push(FilterLog {
            packet_index,
            alerts: vec![alert_info],
        });
    }
}

fn split_pcap(
    input_path: &PathBuf,
    clean_path: &PathBuf,
    quarantine_path: &PathBuf,
    malicious_packets: &HashSet<u64>,
    malicious_flows: &HashSet<Flow>,
    mode: &str,
) -> Result<()> {
    let input_file = File::open(input_path)?;
    let mut pcap_reader = PcapReader::new(input_file)?;

    let clean_file = File::create(clean_path)?;
    let quarantine_file = File::create(quarantine_path)?;

    let mut clean_writer = PcapWriter::new(clean_file)?;
    let mut quarantine_writer = PcapWriter::new(quarantine_file)?;

    let mut packet_number = 1u64;
    let mut clean_count = 0u64;
    let mut quarantine_count = 0u64;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );

    while let Some(packet) = pcap_reader.next_packet() {
        let packet = packet?;

        let is_malicious = if mode == "flow" {
            if let Some(flow) = parse_packet_flow(&packet.data) {
                malicious_flows.contains(&flow)
            } else {
                false
            }
        } else {
            malicious_packets.contains(&packet_number)
        };

        if is_malicious {
            quarantine_writer.write_packet(&packet)?;
            quarantine_count += 1;
        } else {
            clean_writer.write_packet(&packet)?;
            clean_count += 1;
        }

        if packet_number % 10000 == 0 {
            pb.set_message(format!(
                "Processed {} packets (Clean: {}, Quarantine: {})",
                packet_number, clean_count, quarantine_count
            ));
        }
        packet_number += 1;
    }

    pb.finish_with_message(format!(
        "Complete: {} total packets ({} clean, {} quarantined)",
        packet_number - 1,
        clean_count,
        quarantine_count
    ));

    Ok(())
}

fn write_filter_log(log_path: &PathBuf, filter_log: Vec<FilterLog>) -> Result<()> {
    let file = File::create(log_path)?;
    serde_json::to_writer_pretty(file, &filter_log)?;
    info!("Wrote filter log to {:?}", log_path);
    Ok(())
}
