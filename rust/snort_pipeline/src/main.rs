use anyhow::{Context, Result};
use chrono::{Datelike, Local, NaiveDateTime, TimeZone, Utc};
use clap::Parser;
use crossbeam_channel::{Receiver, Sender, bounded};
use etherparse::{InternetSlice, TransportSlice};
use log::{debug, error, info, warn};
use pcap_file::{pcap::PcapReader, pcap::PcapWriter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::sleep;

/// Example Snort 3 JSON Alert Format:
/// { "timestamp" : "07/16-09:23:39.153899", "pkt_num" : 5, "proto" : "TCP", "pkt_gen" : "stream_tcp", "pkt_len" : 97, "dir" : "C2S", "src_ap" : "192.168.1.2:50284", "dst_ap" : "192.168.2.3:80", "rule" : "1:1000000:0", "action" : "would_drop" }

#[derive(Parser, Debug)]
#[command(version, about = "Real-time network traffic analysis pipeline using Snort")]
struct Args {
    /// Network interface to monitor (e.g., "eth0", "Wi-Fi")
    #[arg(short, long)]
    interface: String,

    /// Working directory for temporary files
    #[arg(short, long, default_value = "./pipeline_data")]
    work_dir: PathBuf,

    /// Snort configuration file path
    #[arg(short, long)]
    snort_config: Option<PathBuf>,

    /// Zeek executable path
    #[arg(short, long, default_value = "zeek")]
    zeek_path: String,

    /// ML API endpoint
    #[arg(short, long, default_value = "http://localhost:5000/api/predict")]
    ml_api: String,

    /// Capture duration in seconds
    #[arg(short, long, default_value = "5")]
    duration: u64,

    /// Enable debug mode
    #[arg(long)]
    debug: bool,
}

#[derive(Debug, Clone)]
struct PipelineConfig {
    interface: String,
    work_dir: PathBuf,
    snort_config: Option<PathBuf>,
    zeek_path: String,
    ml_api: String,
    capture_duration: Duration,
    debug: bool,
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

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct SnortAlert {
    timestamp: String,
    #[serde(default)]
    pkt_num: Option<u64>,
    proto: String,
    #[serde(default)]
    pkt_gen: Option<String>,
    #[serde(default)]
    pkt_len: Option<u32>,
    #[serde(default)]
    dir: Option<String>,
    src_ap: String, // Format: "IP:port"
    dst_ap: String, // Format: "IP:port"
    rule: String,   // Format: "gid:sid:rev"
    action: String,
    #[serde(default)]
    msg: Option<String>, // Alert message/signature
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
#[allow(dead_code)]
struct PacketInfo {
    index: u64,
    ts_sec: u32,
    ts_usec: u32,
    flow: Flow,
    hash: Option<String>,
}

// Pipeline message types for inter-thread communication
#[derive(Debug, Clone)]
enum PipelineMessage {
    PcapReady(PathBuf, i64, i64), // (pcap_path, window_start_ts, window_end_ts)
    CleanPcapReady(PathBuf),           // clean_pcap_path
    ConnLogReady(PathBuf),             // conn_log_path
    MLResult(MLResponse),
    Shutdown,
}

#[derive(Debug, Clone)]
struct StoredAlert {
    alert: SnortAlert,
    epoch_ts: Option<i64>,
    ingested_epoch_ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MLResponse {
    #[serde(default = "default_status")]
    status: String,
    #[serde(default)]
    summary: Option<MLSummary>,
    #[serde(default)]
    processing_time_ms: Option<f64>,
    #[serde(default, alias = "predictions")]
    results: Vec<ThreatResult>,
    #[serde(default)]
    timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MLSummary {
    #[serde(alias = "total")]
    total_connections: u32,
    #[serde(alias = "malicious")]
    malicious_count: u32,
    #[serde(alias = "benign")]
    benign_count: u32,
    #[serde(default)]
    avg_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreatResult {
    #[serde(default)]
    id: u32,
    #[serde(default)]
    src_ip: String,
    #[serde(default)]
    src_port: Option<u16>,
    #[serde(default)]
    dst_ip: String,
    #[serde(default)]
    dst_port: Option<u16>,
    #[serde(default, alias = "proto")]
    protocol: String,
    #[serde(default)]
    prediction: Option<Prediction>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    confidence: Option<f64>,
    #[serde(default)]
    is_malicious: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Prediction {
    #[serde(default, alias = "label")]
    class: String,
    #[serde(default)]
    confidence: f64,
    #[serde(default)]
    is_malicious: bool,
}

fn default_status() -> String {
    "ok".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreatSummary {
    connection: String,
    protocol: String,
    threat: String,
    confidence: u32,
}

// Main pipeline orchestrator with separate channels
struct NetworkPipeline {
    config: PipelineConfig,
    filter_tx: Sender<PipelineMessage>,
    filter_rx: Receiver<PipelineMessage>,
    zeek_tx: Sender<PipelineMessage>,
    zeek_rx: Receiver<PipelineMessage>,
    ml_tx: Sender<PipelineMessage>,
    ml_rx: Receiver<PipelineMessage>,
    running_processes: Arc<Mutex<HashMap<String, Child>>>,
    alert_store: Arc<Mutex<Vec<StoredAlert>>>,
}

impl NetworkPipeline {
    // File counter utilities for circular naming (1-100)
    fn get_next_file_id(work_dir: &Path) -> u32 {
        let counter_file = work_dir.join(".file_counter");
        let current_id = if counter_file.exists() {
            std::fs::read_to_string(&counter_file)
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or(1)
        } else {
            1
        };

        let next_id = if current_id >= 100 { 1 } else { current_id + 1 };

        // Save the next ID
        let _ = std::fs::write(&counter_file, next_id.to_string());

        next_id
    }

    fn cleanup_old_files(work_dir: &Path, file_id: u32, base_name: &str) {
        // Clean up files with the same ID from previous cycles
        let patterns = [
            format!("{}_{}.pcap", base_name, file_id),
            format!("clean_{}_{}.pcap", base_name, file_id),
            format!("quarantine_{}_{}.pcap", base_name, file_id),
            format!("quarantine_{}_{}.json", base_name, file_id),
        ];

        for pattern in &patterns {
            let file_path = work_dir.join(pattern);
            if file_path.exists() {
                let _ = std::fs::remove_file(&file_path);
                debug!("Cleaned up old file: {:?}", file_path);
            }
        }

        // Clean up directories
        let dir_patterns = [
            format!("snort_{}_{}", base_name, file_id),
            format!("zeek_clean_{}_{}", base_name, file_id),
        ];

        for pattern in &dir_patterns {
            let dir_path = work_dir.join(pattern);
            if dir_path.exists() {
                let _ = std::fs::remove_dir_all(&dir_path);
                debug!("Cleaned up old directory: {:?}", dir_path);
            }
        }
    }

    fn new(config: PipelineConfig) -> Result<Self> {
        let (filter_tx, filter_rx) = bounded(100);
        let (zeek_tx, zeek_rx) = bounded(100);
        let (ml_tx, ml_rx) = bounded(100);

        Ok(NetworkPipeline {
            config,
            filter_tx,
            filter_rx,
            zeek_tx,
            zeek_rx,
            ml_tx,
            ml_rx,
            running_processes: Arc::new(Mutex::new(HashMap::new())),
            alert_store: Arc::new(Mutex::new(Vec::new())),
        })
    }

    async fn run(&self) -> Result<()> {
        info!("Starting pipeline components...");

        info!("Starting persistent Snort daemon...");
        let _snort_daemon_handle = self.spawn_snort_daemon().await?;

        info!("Starting Snort alert reader...");
        let _alert_reader_handle = self.spawn_alert_reader().await?;

        info!("Starting packet capture component...");
        let _capture_handle = self.spawn_packet_capture().await?;

        info!("Starting PCAP filter component...");
        let _filter_handle = self.spawn_pcap_filter().await?;

        info!("Starting Zeek processor component...");
        let _zeek_handle = self.spawn_zeek_processor().await?;

        info!("Starting ML client component...");
        let _ml_handle = self.spawn_ml_client().await?;

        info!("All pipeline components started successfully!");

        // Keep the main thread alive - components communicate directly
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            info!("Pipeline running...");
        }
    }

    async fn spawn_packet_capture(&self) -> Result<tokio::task::JoinHandle<()>> {
        let interface = self.config.interface.clone();
        let work_dir = self.config.work_dir.clone();
        let duration = self.config.capture_duration;
        let filter_tx = self.filter_tx.clone();

        let handle = tokio::spawn(async move {
            loop {
                match NetworkPipeline::capture_traffic(&interface, &work_dir, duration).await {
                    Ok((pcap_path, start_ts, end_ts)) => {
                        if let Err(e) = filter_tx.send(PipelineMessage::PcapReady(
                            pcap_path.clone(),
                            start_ts,
                            end_ts,
                        )) {
                            error!("Failed to send PCAP to filter: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to capture traffic: {}", e);
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn capture_traffic(
        interface: &str,
        work_dir: &Path,
        duration: Duration,
    ) -> Result<(PathBuf, i64, i64)> {
        let start_time = std::time::Instant::now();
        let file_id = Self::get_next_file_id(work_dir);

        // Clean up old files with this ID
        Self::cleanup_old_files(work_dir, file_id, "capture");

        let pcap_file = work_dir.join(format!("capture_{}.pcap", file_id));

        info!(
            "Capturing traffic (ID: {}) on {} for {}s...",
            file_id,
            interface,
            duration.as_secs()
        );

        // Use dumpcap (part of Wireshark) or tcpdump for packet capture
        let mut cmd = if cfg!(target_os = "windows") {
            // Windows: Use dumpcap
            let mut c = Command::new("dumpcap");
            c.args(&[
                "-i",
                interface,
                "-a",
                &format!("duration:{}", duration.as_secs()),
                "-w",
                pcap_file.to_str().unwrap(),
                "-q", // Quiet mode
            ]);
            c
        } else {
            // Linux/Unix: Use tcpdump
            let mut c = Command::new("tcpdump");
            c.args(&[
                "-i",
                interface,
                "-G",
                &format!("{}", duration.as_secs()),
                "-W",
                "1", // Only one file
                "-w",
                pcap_file.to_str().unwrap(),
                "-s",
                "65535", // Capture full packets
            ]);
            c
        };

        let output = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?
            .wait_with_output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Packet capture failed: {}", stderr));
        }

        let capture_duration = start_time.elapsed();
        info!(
            "Captured {} in {:.1}s",
            pcap_file.file_name().unwrap().to_str().unwrap(),
            capture_duration.as_secs_f32()
        );

        let end_ts = Utc::now().timestamp();
        let start_ts = end_ts - duration.as_secs() as i64;

        Ok((pcap_file, start_ts, end_ts))
    }

    async fn spawn_snort_daemon(&self) -> Result<tokio::task::JoinHandle<()>> {
        let interface = self.config.interface.clone();
        let config_path = self
            .config
            .snort_config
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/etc/snort/snort.lua".to_string());
        let live_dir = self.config.work_dir.join("snort_live");

        std::fs::create_dir_all(&live_dir)?;

        info!(
            "Launching Snort daemon with config={} interface={} log_dir={}",
            config_path,
            interface,
            live_dir.display()
        );

        let mut cmd = Command::new("snort");
        cmd.arg("-c")
            .arg(config_path)
            .arg("-i")
            .arg(interface)
            .arg("-l")
            .arg(&live_dir)
            .arg("-A")
            .arg("alert_json")
            .arg("-q")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn().context("Failed to start persistent Snort")?;

        {
            let mut processes = self.running_processes.lock().unwrap();
            processes.insert("snort_daemon".to_string(), child);
        }

        let running_processes = self.running_processes.clone();
        let handle = tokio::spawn(async move {
            loop {
                let exited_child = {
                    let mut processes = running_processes.lock().unwrap();
                    let child = match processes.get_mut("snort_daemon") {
                        Some(c) => c,
                        None => break,
                    };

                    let exited = match child.try_wait() {
                        Ok(Some(_)) => true,
                        Ok(None) => false,
                        Err(e) => {
                            error!("Failed checking Snort daemon status: {}", e);
                            false
                        }
                    };

                    if exited {
                        processes.remove("snort_daemon")
                    } else {
                        None
                    }
                };

                if let Some(child) = exited_child {
                    match child.wait_with_output() {
                        Ok(output) => {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);

                            error!(
                                "Snort daemon exited unexpectedly: {:?}",
                                output.status.code()
                            );
                            if !stdout.trim().is_empty() {
                                error!("Snort daemon stdout:\n{}", stdout);
                            }
                            if !stderr.trim().is_empty() {
                                error!("Snort daemon stderr:\n{}", stderr);
                            }
                        }
                        Err(e) => {
                            error!("Snort daemon exited and output could not be read: {}", e);
                        }
                    }
                    break;
                }

                sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(handle)
    }

    async fn spawn_alert_reader(&self) -> Result<tokio::task::JoinHandle<()>> {
        let alert_store = self.alert_store.clone();
        let alert_file_path = self.config.work_dir.join("snort_live").join("alert_json.txt");

        let handle = tokio::spawn(async move {
            info!("Snort alert reader started");
            let mut offset: u64 = 0;

            loop {
                if !alert_file_path.exists() {
                    sleep(Duration::from_millis(250)).await;
                    continue;
                }

                let file = match File::open(&alert_file_path) {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Failed to open Snort alert stream file: {}", e);
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                };

                let metadata_len = match file.metadata() {
                    Ok(m) => m.len(),
                    Err(_) => 0,
                };

                if metadata_len < offset {
                    offset = 0;
                }

                let mut reader = BufReader::new(file);
                if reader.seek_relative(offset as i64).is_err() {
                    offset = 0;
                    sleep(Duration::from_millis(250)).await;
                    continue;
                }

                let mut line = String::new();
                loop {
                    line.clear();
                    let bytes = match reader.read_line(&mut line) {
                        Ok(n) => n,
                        Err(e) => {
                            error!("Failed reading Snort alert stream: {}", e);
                            break;
                        }
                    };

                    if bytes == 0 {
                        break;
                    }

                    offset += bytes as u64;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    match serde_json::from_str::<SnortAlert>(trimmed) {
                        Ok(alert) => {
                            let epoch_ts = parse_snort_timestamp_epoch(&alert.timestamp);
                            let ingested_epoch_ts = Utc::now().timestamp();
                            let mut store = alert_store.lock().unwrap();
                            store.push(StoredAlert {
                                alert,
                                epoch_ts,
                                ingested_epoch_ts,
                            });

                            if store.len() > 50_000 {
                                let drop_count = store.len() - 50_000;
                                store.drain(0..drop_count);
                            }
                        }
                        Err(e) => {
                            debug!("Failed to parse Snort alert JSON stream line: {}", e);
                        }
                    }
                }

                sleep(Duration::from_millis(250)).await;
            }
        });

        Ok(handle)
    }

    async fn spawn_pcap_filter(&self) -> Result<tokio::task::JoinHandle<()>> {
        let filter_rx = self.filter_rx.clone();
        let zeek_tx = self.zeek_tx.clone();
        let work_dir = self.config.work_dir.clone();
        let alert_store = self.alert_store.clone();

        let handle = tokio::spawn(async move {
            info!("PCAP filter started");

            loop {
                match filter_rx.recv() {
                    Ok(PipelineMessage::PcapReady(pcap_path, window_start_ts, window_end_ts)) => {
                        let start_time = std::time::Instant::now();

                        match NetworkPipeline::filter_pcap(
                            &pcap_path,
                            &work_dir,
                            &alert_store,
                            window_start_ts,
                            window_end_ts,
                        )
                        .await
                        {
                            Ok(clean_path) => {
                                let duration = start_time.elapsed();
                                info!(
                                    "Filtered in {:.1}s: {}",
                                    duration.as_secs_f32(),
                                    clean_path.file_name().unwrap().to_str().unwrap()
                                );

                                if let Err(e) =
                                    zeek_tx.send(PipelineMessage::CleanPcapReady(clean_path))
                                {
                                    error!("Failed to send to Zeek: {}", e);
                                }
                            }
                            Err(e) => {
                                let duration = start_time.elapsed();
                                error!("Filter failed in {:.1}s: {}", duration.as_secs_f32(), e);
                            }
                        }
                    }
                    Ok(PipelineMessage::Shutdown) => {
                        info!("PCAP filter shutting down");
                        break;
                    }
                    Ok(_) => {
                        // Ignore other message types
                    }
                    Err(e) => {
                        error!("Error receiving message in PCAP filter: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn filter_pcap(
        pcap_path: &Path,
        work_dir: &Path,
        alert_store: &Arc<Mutex<Vec<StoredAlert>>>,
        window_start_ts: i64,
        window_end_ts: i64,
    ) -> Result<PathBuf> {
        // Extract file ID from the input PCAP filename
        let file_stem = pcap_path.file_stem().unwrap().to_str().unwrap();

        let clean_path = work_dir.join(format!("clean_{}.pcap", file_stem));
        let quarantine_path = work_dir.join(format!("quarantine_{}.pcap", file_stem));

        // Check if input PCAP file exists and has content
        if !pcap_path.exists() {
            return Err(anyhow::anyhow!(
                "Input PCAP file does not exist: {:?}",
                pcap_path
            ));
        }

        let file_size = std::fs::metadata(pcap_path)?.len();

        if file_size == 0 {
            warn!("Input PCAP file is empty, creating empty clean PCAP");
            // Create an empty but valid PCAP file
            let empty_file = File::create(&clean_path)?;
            let mut empty_writer = PcapWriter::new(empty_file)?;
            drop(empty_writer);
            return Ok(clean_path);
        }

        // Use the existing filter logic
        let mut packet_index = Vec::new();
        let mut malicious_packets = HashSet::new();
        let mut malicious_flows = HashSet::new();
        let mut filter_log = Vec::new();

        // Index the PCAP file
        index_pcap(pcap_path, &mut packet_index)?;

        if packet_index.is_empty() {
            warn!("No packets found in PCAP file, creating empty clean PCAP");
            // Create an empty but valid PCAP file
            let empty_file = File::create(&clean_path)?;
            let mut empty_writer = PcapWriter::new(empty_file)?;
            drop(empty_writer);
            return Ok(clean_path);
        }

        let (window_alerts, parsed_ts_matches, ingested_ts_matches, total_cached_alerts) = {
            let alerts = alert_store.lock().unwrap();
            let total_cached_alerts = alerts.len();
            let mut parsed_ts_matches = 0usize;
            let mut ingested_ts_matches = 0usize;
            let window_alerts = alerts
                .iter()
                .filter(|a| {
                    let parsed_match = a
                        .epoch_ts
                        .map(|ts| ts >= window_start_ts - 1 && ts <= window_end_ts + 1)
                        .unwrap_or(false);

                    if parsed_match {
                        parsed_ts_matches += 1;
                        return true;
                    }

                    let ingested_match =
                        a.ingested_epoch_ts >= window_start_ts - 1 && a.ingested_epoch_ts <= window_end_ts + 1;
                    if ingested_match {
                        ingested_ts_matches += 1;
                    }
                    ingested_match
                })
                .map(|a| a.alert.clone())
                .collect::<Vec<_>>();

            (
                window_alerts,
                parsed_ts_matches,
                ingested_ts_matches,
                total_cached_alerts,
            )
        };

        info!(
            "Selected {} alerts for window [{}..{}] from {} cached (parsed_ts_matches={}, ingested_ts_matches={})",
            window_alerts.len(),
            window_start_ts,
            window_end_ts,
            total_cached_alerts,
            parsed_ts_matches,
            ingested_ts_matches
        );

        // Process Snort alerts collected during the capture window
        process_snort_alerts(
            &window_alerts,
            &packet_index,
            &mut malicious_packets,
            &mut malicious_flows,
            &mut filter_log,
            "packet",
        )?;

        // Split PCAP
        split_pcap(
            pcap_path,
            &clean_path,
            &quarantine_path,
            &malicious_packets,
            &malicious_flows,
            "packet",
        )?;

        // Write filter log
        let log_path = quarantine_path.with_extension("json");
        write_filter_log(&log_path, filter_log)?;

        // Verify clean PCAP was created
        if !clean_path.exists() {
            return Err(anyhow::anyhow!(
                "Clean PCAP file was not created: {:?}",
                clean_path
            ));
        }

        // Small delay to ensure file is completely written before Zeek reads it
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        Ok(clean_path)
    }

    async fn spawn_zeek_processor(&self) -> Result<tokio::task::JoinHandle<()>> {
        let zeek_rx = self.zeek_rx.clone();
        let ml_tx = self.ml_tx.clone();
        let work_dir = self.config.work_dir.clone();
        let zeek_path = self.config.zeek_path.clone();

        let handle = tokio::spawn(async move {
            info!("Zeek processor started");

            loop {
                match zeek_rx.recv() {
                    Ok(PipelineMessage::CleanPcapReady(clean_pcap_path)) => {
                        let start_time = std::time::Instant::now();

                        match NetworkPipeline::run_zeek(&clean_pcap_path, &work_dir, &zeek_path)
                            .await
                        {
                            Ok(conn_log_path) => {
                                let duration = start_time.elapsed();
                                info!(
                                    "Zeek analysis completed in {:.1}s: {}",
                                    duration.as_secs_f32(),
                                    clean_pcap_path.file_name().unwrap().to_str().unwrap()
                                );

                                if let Err(e) =
                                    ml_tx.send(PipelineMessage::ConnLogReady(conn_log_path))
                                {
                                    error!("Failed to send to ML: {}", e);
                                }
                            }
                            Err(e) => {
                                let duration = start_time.elapsed();
                                error!("Zeek failed in {:.1}s: {}", duration.as_secs_f32(), e);
                            }
                        }
                    }
                    Ok(PipelineMessage::Shutdown) => {
                        info!("Zeek processor shutting down");
                        break;
                    }
                    Ok(_) => {
                        // Ignore other message types
                    }
                    Err(e) => {
                        error!("Error receiving message in Zeek processor: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn run_zeek(pcap_path: &Path, work_dir: &Path, zeek_path: &str) -> Result<PathBuf> {
        // Extract file ID from the input PCAP filename
        let file_stem = pcap_path.file_stem().unwrap().to_str().unwrap();

        let zeek_output_dir = work_dir.join(format!("zeek_{}", file_stem));

        std::fs::create_dir_all(&zeek_output_dir)?;

        // Convert to absolute path to avoid Zeek path resolution issues
        let absolute_pcap_path = pcap_path.canonicalize()?;

        // Check if PCAP file exists and has content
        if !absolute_pcap_path.exists() {
            return Err(anyhow::anyhow!(
                "PCAP file does not exist: {:?}",
                absolute_pcap_path
            ));
        }

        let file_size = std::fs::metadata(&absolute_pcap_path)?.len();

        if file_size <= 24 {
            // PCAP header is 24 bytes, so if smaller/equal, it's empty
            warn!("PCAP file is empty or too small for Zeek processing");
            // Create an empty conn.log file
            let conn_log_path = zeek_output_dir.join("conn.log");
            std::fs::write(
                &conn_log_path,
                "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n",
            )?;
            return Ok(conn_log_path);
        }

        // Double-check file exists just before running Zeek
        if !absolute_pcap_path.exists() {
            return Err(anyhow::anyhow!(
                "PCAP file disappeared before Zeek processing: {:?}",
                absolute_pcap_path
            ));
        }

        let output = Command::new("sudo")
            .arg(zeek_path)
            .arg("-r")
            .arg(absolute_pcap_path.to_str().unwrap())
            .arg("-C") // Ignore checksums
            .current_dir(&zeek_output_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?
            .wait_with_output()?;

        // Always log Zeek output for debugging
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !stdout.is_empty() {
            info!("Zeek stdout: {}", stdout);
        }
        if !stderr.is_empty() {
            info!("Zeek stderr: {}", stderr);
        }

        if !output.status.success() {
            error!("Zeek failed with exit code: {:?}", output.status.code());
            return Err(anyhow::anyhow!("Zeek failed: {}", stderr));
        }

        let conn_log_path = zeek_output_dir.join("conn.log");
        if !conn_log_path.exists() {
            warn!("Zeek didn't generate conn.log (no connections found), creating empty log");
            // Create an empty conn.log with proper headers
            std::fs::write(
                &conn_log_path,
                "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n#close\t2024-01-01-00-00-00\n",
            )?;
        } else {
            // Check if the conn.log actually has connection data
            let content = std::fs::read_to_string(&conn_log_path)?;
            let data_lines = content
                .lines()
                .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
                .count();

            if data_lines == 0 {
                warn!("Zeek generated conn.log but it contains no connection data");
                info!(
                    "conn.log headers only - this indicates no TCP/UDP connections were established"
                );
            }
        }

        Ok(conn_log_path)
    }

    async fn spawn_ml_client(&self) -> Result<tokio::task::JoinHandle<()>> {
        let ml_rx = self.ml_rx.clone();
        let ml_api = self.config.ml_api.clone();

        let handle = tokio::spawn(async move {
            info!("ML client started");
            let client = reqwest::Client::new();

            loop {
                match ml_rx.recv() {
                    Ok(PipelineMessage::ConnLogReady(conn_log_path)) => {
                        let start_time = std::time::Instant::now();

                        match NetworkPipeline::call_ml_api(&client, &conn_log_path, &ml_api).await {
                            Ok(response) => {
                                let duration = start_time.elapsed();
                                info!("ML analysis completed in {:.1}s", duration.as_secs_f32());
                                NetworkPipeline::process_ml_response(&response);
                            }
                            Err(e) => {
                                let duration = start_time.elapsed();
                                error!("ML failed in {:.1}s: {}", duration.as_secs_f32(), e);
                            }
                        }
                    }
                    Ok(PipelineMessage::Shutdown) => {
                        info!("ML client shutting down");
                        break;
                    }
                    Ok(_) => {
                        // Ignore other message types
                    }
                    Err(e) => {
                        error!("Error receiving message in ML client: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn call_ml_api(
        client: &reqwest::Client,
        conn_log_path: &Path,
        api_url: &str,
    ) -> Result<MLResponse> {
        // Check if conn.log has actual data before sending to ML API
        let file_content = tokio::fs::read_to_string(conn_log_path).await?;
        let data_lines: Vec<&str> = file_content
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .collect();

        if data_lines.is_empty() {
            info!("conn.log is empty (no connections), skipping ML analysis");
            return Ok(MLResponse {
                status: "success".to_string(),
                summary: Some(MLSummary {
                    total_connections: 0,
                    malicious_count: 0,
                    benign_count: 0,
                    avg_confidence: 0.0,
                }),
                processing_time_ms: Some(0.0),
                results: vec![],
                timestamp: None,
            });
        }

        // Convert back to bytes for upload
        let file_content_bytes = file_content.into_bytes();

        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(file_content_bytes)
                .file_name("conn.log")
                .mime_str("text/plain")?,
        );

        let response = client
            .post(api_url)
            .timeout(std::time::Duration::from_secs(30))
            .multipart(form)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("ML API error response body: {}", error_text);
            return Err(anyhow::anyhow!(
                "ML API returned error {}: {}",
                status,
                error_text
            ));
        }

        let ml_response: MLResponse = response.json().await?;
        Ok(ml_response)
    }

    fn process_ml_response(response: &MLResponse) {
        info!("ML Analysis Status: {}", response.status);

        if let Some(summary) = &response.summary {
            info!(
                "ML Analysis Summary: {} total connections, {} malicious, {} benign (avg confidence: {:.2})",
                summary.total_connections,
                summary.malicious_count,
                summary.benign_count,
                summary.avg_confidence
            );
        }

        if let Some(time_ms) = response.processing_time_ms {
            info!("ML Processing Time: {:.2}ms", time_ms);
        }

        let high_confidence_threats: Vec<ThreatSummary> = response
            .results
            .iter()
            .filter_map(|result| {
                let (threat_class, confidence, is_malicious) =
                    Self::prediction_values(result);
                if confidence > 0.95 && is_malicious {
                    Some(ThreatSummary {
                        connection: format!(
                            "{}:{} → {}:{}",
                            result.src_ip,
                            result.src_port.map_or("-".to_string(), |p| p.to_string()),
                            result.dst_ip,
                            result.dst_port.map_or("-".to_string(), |p| p.to_string())
                        ),
                        protocol: if result.protocol.is_empty() {
                            "unknown".to_string()
                        } else {
                            result.protocol.clone()
                        },
                        threat: threat_class,
                        confidence: (confidence * 100.0).round() as u32,
                    })
                } else {
                    None
                }
            })
            .collect();

        if !high_confidence_threats.is_empty() {
            warn!("High-confidence threats detected:");
            for threat in high_confidence_threats {
                warn!(
                    "  {} [{}] - {} ({}% confidence)",
                    threat.connection, threat.protocol, threat.threat, threat.confidence
                );
            }
        } else {
            info!("No high-confidence threats detected");
        }

        // Log malicious connections at any confidence level
        let malicious_connections: Vec<_> = response
            .results
            .iter()
            .filter(|result| {
                let (_, _, is_malicious) = Self::prediction_values(result);
                is_malicious
            })
            .collect();

        if !malicious_connections.is_empty() {
            info!(
                "Found {} potentially malicious connections:",
                malicious_connections.len()
            );
            for result in malicious_connections.iter().take(5) {
                // Show first 5
                let (threat_class, confidence, _) = Self::prediction_values(result);
                info!(
                    "  {}:{} → {}:{} [{}] - {} ({:.1}% confidence)",
                    result.src_ip,
                    result.src_port.map_or("-".to_string(), |p| p.to_string()),
                    result.dst_ip,
                    result.dst_port.map_or("-".to_string(), |p| p.to_string()),
                    if result.protocol.is_empty() {
                        "unknown"
                    } else {
                        &result.protocol
                    },
                    threat_class,
                    confidence * 100.0
                );
            }
            if malicious_connections.len() > 5 {
                info!("  ... and {} more", malicious_connections.len() - 5);
            }
        }
    }

    fn prediction_values(result: &ThreatResult) -> (String, f64, bool) {
        if let Some(prediction) = &result.prediction {
            let class = if prediction.class.is_empty() {
                "Unknown".to_string()
            } else {
                prediction.class.clone()
            };
            return (class, prediction.confidence, prediction.is_malicious);
        }

        (
            result
                .label
                .clone()
                .unwrap_or_else(|| "Unknown".to_string()),
            result.confidence.unwrap_or(0.0),
            result.is_malicious.unwrap_or(false),
        )
    }

    async fn cleanup_processes(&self) -> Result<()> {
        let mut processes = self.running_processes.lock().unwrap();
        for (name, mut process) in processes.drain() {
            info!("Terminating process: {}", name);
            let _ = process.kill();
            let _ = process.wait();
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let config = PipelineConfig {
        interface: args.interface,
        work_dir: args.work_dir,
        snort_config: args.snort_config,
        zeek_path: args.zeek_path,
        ml_api: args.ml_api,
        capture_duration: Duration::from_secs(args.duration),
        debug: args.debug,
    };

    info!("Starting real-time network analysis pipeline with Snort");
    info!("Interface: {}", config.interface);
    info!("Capture duration: {:?}", config.capture_duration);
    info!("Work directory: {:?}", config.work_dir);

    // Optional: Clean up all old pipeline files on startup
    if let Ok(entries) = std::fs::read_dir(&config.work_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("capture_")
                    || name.starts_with("clean_")
                    || name.starts_with("quarantine_")
                    || name.starts_with("snort_")
                    || name.starts_with("zeek_")
                {
                    if path.is_file() {
                        let _ = std::fs::remove_file(&path);
                    } else if path.is_dir() {
                        let _ = std::fs::remove_dir_all(&path);
                    }
                }
            }
        }
        info!("Cleaned up old pipeline files from previous runs");
    }

    // Create work directory if it doesn't exist
    std::fs::create_dir_all(&config.work_dir)?;

    // Initialize file counter (start fresh)
    let counter_file = config.work_dir.join(".file_counter");
    std::fs::write(&counter_file, "0")?;
    info!("Initialized circular file naming system (1-100)");

    // Start the real-time pipeline
    let pipeline = NetworkPipeline::new(config)?;
    pipeline.run().await?;

    Ok(())
}

fn index_pcap(input_path: &Path, packet_index: &mut Vec<PacketInfo>) -> Result<()> {
    let file = File::open(input_path).context("Failed to open input pcap")?;
    let mut pcap_reader = PcapReader::new(file)?;
    let mut packet_number = 1u64;

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

        packet_number += 1;
    }

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

fn process_snort_alerts(
    alerts: &[SnortAlert],
    packet_index: &[PacketInfo],
    malicious_packets: &mut HashSet<u64>,
    malicious_flows: &mut HashSet<Flow>,
    filter_log: &mut Vec<FilterLog>,
    mode: &str,
) -> Result<()> {
    info!("Processing {} Snort 3 alerts from live stream cache...", alerts.len());

    for snort_alert in alerts {
        // In live mode, Snort pkt_num is global to the running sensor and usually
        // does not match per-window PCAP packet numbering (1..N). Only use it when
        // it is within the current indexed packet range.
        if let Some(pkt_num) = snort_alert.pkt_num {
            let max_index = packet_index.len() as u64;
            if pkt_num > 0 && pkt_num <= max_index {
                malicious_packets.insert(pkt_num);
                record_snort_alert(filter_log, pkt_num, snort_alert);
            }
        }

        // Parse src_ap and dst_ap (format: "IP:port")
        let (src_ip, src_port) = parse_address_port(&snort_alert.src_ap);
        let (dst_ip, dst_port) = parse_address_port(&snort_alert.dst_ap);

        // Flow-based matching is the primary strategy for live Snort alerts.
        if mode == "flow" {
            if let (Ok(src_ip_addr), Ok(dst_ip_addr)) = (src_ip.parse(), dst_ip.parse()) {
                let flow = Flow {
                    src_ip: src_ip_addr,
                    dst_ip: dst_ip_addr,
                    src_port,
                    dst_port,
                    protocol: protocol_str_to_num(&snort_alert.proto),
                };
                malicious_flows.insert(flow);
            }
        } else {
            // Flow-based packet matching (match packets by flow characteristics)
            if let (Ok(src_ip_addr), Ok(dst_ip_addr)) = (src_ip.parse(), dst_ip.parse()) {
                let alert_flow = Flow {
                    src_ip: src_ip_addr,
                    dst_ip: dst_ip_addr,
                    src_port,
                    dst_port,
                    protocol: protocol_str_to_num(&snort_alert.proto),
                };

                for packet in packet_index {
                    if packet.flow == alert_flow {
                        malicious_packets.insert(packet.index);
                        record_snort_alert(filter_log, packet.index, snort_alert);
                    }
                }
            }
        }
    }

    Ok(())
}

fn parse_snort_timestamp_epoch(ts: &str) -> Option<i64> {
    // Snort 3 alert_json timestamp format: MM/DD-HH:MM:SS.ffffff
    let year = Local::now().year();
    let full_ts = format!("{}/{}", year, ts);
    let naive = NaiveDateTime::parse_from_str(&full_ts, "%Y/%m/%d-%H:%M:%S%.6f").ok()?;

    // Snort timestamps are local wall-clock time with no timezone. Interpret in local timezone.
    if let Some(local_dt) = Local.from_local_datetime(&naive).single() {
        return Some(local_dt.timestamp());
    }

    Local
        .from_local_datetime(&naive)
        .earliest()
        .map(|dt| dt.timestamp())
}

fn protocol_str_to_num(proto: &str) -> u8 {
    match proto.to_uppercase().as_str() {
        "TCP" => 6,
        "UDP" => 17,
        "ICMP" => 1,
        _ => 0,
    }
}

// Parse Snort 3's "IP:port" format
fn parse_address_port(addr_port: &str) -> (String, u16) {
    if let Some(last_colon) = addr_port.rfind(':') {
        let ip = addr_port[..last_colon].to_string();
        let port = addr_port[last_colon + 1..].parse().unwrap_or(0);
        (ip, port)
    } else {
        (addr_port.to_string(), 0)
    }
}

fn record_snort_alert(filter_log: &mut Vec<FilterLog>, packet_index: u64, alert: &SnortAlert) {
    // Parse rule field (format: "gid:sid:rev")
    let rule_parts: Vec<&str> = alert.rule.split(':').collect();
    let signature_id = if rule_parts.len() >= 2 {
        rule_parts[1].parse().unwrap_or(0)
    } else {
        0
    };

    let alert_info = AlertInfo {
        signature_id,
        signature: alert.msg.clone().unwrap_or_else(|| alert.rule.clone()),
        timestamp: alert.timestamp.clone(),
        src: alert.src_ap.clone(),
        dst: alert.dst_ap.clone(),
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
    input_path: &Path,
    clean_path: &Path,
    quarantine_path: &Path,
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

        packet_number += 1;
    }

    info!(
        "Packet filtering complete: {} clean packets, {} quarantined packets",
        clean_count, quarantine_count
    );

    Ok(())
}

fn write_filter_log(log_path: &Path, filter_log: Vec<FilterLog>) -> Result<()> {
    let file = File::create(log_path)?;
    serde_json::to_writer_pretty(file, &filter_log)?;
    Ok(())
}
