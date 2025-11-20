use anyhow::{Context, Result};
use chrono::DateTime;
use clap::Parser;
use crossbeam_channel::{Receiver, Sender, bounded};
use etherparse::{InternetSlice, TransportSlice};
use log::{debug, error, info, warn};
use pcap_file::{pcap::PcapReader, pcap::PcapWriter};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
#[command(version, about = "Real-time network traffic analysis pipeline")]
struct Args {
    /// Network interface to monitor (e.g., "eth0", "Wi-Fi")
    #[arg(short, long)]
    interface: String,

    /// Working directory for temporary files
    #[arg(short, long, default_value = "./pipeline_data")]
    work_dir: PathBuf,

    /// Suricata configuration file path
    #[arg(short, long)]
    suricata_config: Option<PathBuf>,

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
    suricata_config: Option<PathBuf>,
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

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
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
    NewPcapFile(PathBuf),
    EveJsonReady(PathBuf, PathBuf), // (eve_json_path, original_pcap_path)
    CleanPcapReady(PathBuf),        // clean_pcap_path
    ConnLogReady(PathBuf),          // conn_log_path
    MLResult(MLResponse),
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MLResponse {
    status: String,
    summary: Option<MLSummary>,
    processing_time_ms: Option<f64>,
    results: Vec<ThreatResult>,
    timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MLSummary {
    total_connections: u32,
    malicious_count: u32,
    benign_count: u32,
    avg_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreatResult {
    id: u32,
    src_ip: String,
    src_port: Option<u16>,
    dst_ip: String,
    dst_port: Option<u16>,
    protocol: String,
    prediction: Prediction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Prediction {
    class: String,
    confidence: f64,
    is_malicious: bool,
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
    // Separate channels for each component
    suricata_tx: Sender<PipelineMessage>,
    suricata_rx: Receiver<PipelineMessage>,
    filter_tx: Sender<PipelineMessage>,
    filter_rx: Receiver<PipelineMessage>,
    zeek_tx: Sender<PipelineMessage>,
    zeek_rx: Receiver<PipelineMessage>,
    ml_tx: Sender<PipelineMessage>,
    ml_rx: Receiver<PipelineMessage>,
    running_processes: Arc<Mutex<HashMap<String, Child>>>,
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
                debug!("🗑️ Cleaned up old file: {:?}", file_path);
            }
        }

        // Clean up directories
        let dir_patterns = [
            format!("suricata_{}_{}", base_name, file_id),
            format!("zeek_clean_{}_{}", base_name, file_id),
        ];

        for pattern in &dir_patterns {
            let dir_path = work_dir.join(pattern);
            if dir_path.exists() {
                let _ = std::fs::remove_dir_all(&dir_path);
                debug!("🗑️ Cleaned up old directory: {:?}", dir_path);
            }
        }
    }

    fn new(config: PipelineConfig) -> Result<Self> {
        let (suricata_tx, suricata_rx) = bounded(100);
        let (filter_tx, filter_rx) = bounded(100);
        let (zeek_tx, zeek_rx) = bounded(100);
        let (ml_tx, ml_rx) = bounded(100);

        Ok(NetworkPipeline {
            config,
            suricata_tx,
            suricata_rx,
            filter_tx,
            filter_rx,
            zeek_tx,
            zeek_rx,
            ml_tx,
            ml_rx,
            running_processes: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn run(&self) -> Result<()> {
        info!("Starting pipeline components...");

        // Spawn all pipeline components with individual logging
        info!("🚀 Starting packet capture component...");
        let _capture_handle = self.spawn_packet_capture().await?;

        info!("🚀 Starting Suricata monitor component...");
        let _suricata_handle = self.spawn_suricata_monitor().await?;

        info!("🚀 Starting PCAP filter component...");
        let _filter_handle = self.spawn_pcap_filter().await?;

        info!("🚀 Starting Zeek processor component...");
        let _zeek_handle = self.spawn_zeek_processor().await?;

        info!("🚀 Starting ML client component...");
        let _ml_handle = self.spawn_ml_client().await?;

        info!("✅ All pipeline components started successfully!");

        // Keep the main thread alive - components communicate directly
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            info!("🔄 Pipeline running...");
        }
    }

    async fn spawn_packet_capture(&self) -> Result<tokio::task::JoinHandle<()>> {
        let interface = self.config.interface.clone();
        let work_dir = self.config.work_dir.clone();
        let duration = self.config.capture_duration;
        let suricata_tx = self.suricata_tx.clone();

        let handle = tokio::spawn(async move {
            loop {
                match NetworkPipeline::capture_traffic(&interface, &work_dir, duration).await {
                    Ok(pcap_path) => {
                        if let Err(e) =
                            suricata_tx.send(PipelineMessage::NewPcapFile(pcap_path.clone()))
                        {
                            error!("❌ Failed to send to Suricata: {}", e);
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
    ) -> Result<PathBuf> {
        let start_time = std::time::Instant::now();
        let file_id = Self::get_next_file_id(work_dir);

        // Clean up old files with this ID
        Self::cleanup_old_files(work_dir, file_id, "capture");

        let pcap_file = work_dir.join(format!("capture_{}.pcap", file_id));

        info!(
            "📦 Capturing traffic (ID: {}) on {} for {}s...",
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
            "✅ Captured {} in {:.1}s",
            pcap_file.file_name().unwrap().to_str().unwrap(),
            capture_duration.as_secs_f32()
        );

        Ok(pcap_file)
    }

    async fn spawn_suricata_monitor(&self) -> Result<tokio::task::JoinHandle<()>> {
        let suricata_rx = self.suricata_rx.clone();
        let filter_tx = self.filter_tx.clone();
        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            info!("🔍 Suricata monitor started");

            loop {
                match suricata_rx.recv_timeout(std::time::Duration::from_secs(10)) {
                    Ok(PipelineMessage::NewPcapFile(pcap_path)) => {
                        let start_time = std::time::Instant::now();

                        match NetworkPipeline::run_suricata(
                            &pcap_path,
                            config.suricata_config.as_ref(),
                        )
                        .await
                        {
                            Ok(eve_json_path) => {
                                let duration = start_time.elapsed();
                                info!(
                                    "✅ Suricata analysis completed in {:.1}s: {}",
                                    duration.as_secs_f32(),
                                    pcap_path.file_name().unwrap().to_str().unwrap()
                                );

                                if let Err(e) = filter_tx
                                    .send(PipelineMessage::EveJsonReady(eve_json_path, pcap_path))
                                {
                                    error!("Failed to send to filter: {}", e);
                                }
                            }
                            Err(e) => {
                                let duration = start_time.elapsed();
                                error!(
                                    "❌ Suricata failed in {:.1}s for {}: {}",
                                    duration.as_secs_f32(),
                                    pcap_path.file_name().unwrap().to_str().unwrap(),
                                    e
                                );
                            }
                        }
                    }
                    Ok(PipelineMessage::Shutdown) => {
                        info!("🛑 Suricata monitor shutting down");
                        break;
                    }
                    Ok(_) => {
                        // Ignore other message types
                    }
                    Err(_timeout) => {
                        // Timeout - continue waiting
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn run_suricata(pcap_path: &Path, config: Option<&PathBuf>) -> Result<PathBuf> {
        let config_path = config
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/etc/suricata/suricata.yaml".to_string());

        let output_dir = pcap_path
            .parent()
            .context("Failed to get PCAP directory")?
            .join(format!(
                "suricata_{}",
                pcap_path
                    .file_stem()
                    .context("Failed to get PCAP filename")?
                    .to_string_lossy()
            ));

        std::fs::create_dir_all(&output_dir)
            .context("Failed to create Suricata output directory")?;

        // Suricata analysis starting (timing handled by caller)

        let output = Command::new("suricata")
            .arg("-c")
            .arg(&config_path)
            .arg("-r")
            .arg(pcap_path)
            .arg("-l")
            .arg(&output_dir)
            .arg("-v") // Add verbose flag
            .output()
            .context("Failed to execute Suricata")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
            error!("Suricata stderr: {}", stderr);
            error!("Suricata stdout: {}", stdout);
            return Err(anyhow::anyhow!(
                "Suricata failed with exit code: {:?}",
                output.status.code()
            ));
        }

        let eve_json_path = output_dir.join("eve.json");
        if !eve_json_path.exists() {
            return Err(anyhow::anyhow!(
                "Suricata did not create eve.json at {:?}",
                eve_json_path
            ));
        }

        Ok(eve_json_path)
    }

    async fn spawn_pcap_filter(&self) -> Result<tokio::task::JoinHandle<()>> {
        let filter_rx = self.filter_rx.clone();
        let zeek_tx = self.zeek_tx.clone();
        let work_dir = self.config.work_dir.clone();

        let handle = tokio::spawn(async move {
            info!("🧹 PCAP filter started");

            loop {
                match filter_rx.recv() {
                    Ok(PipelineMessage::EveJsonReady(eve_path, pcap_path)) => {
                        let start_time = std::time::Instant::now();

                        match NetworkPipeline::filter_pcap(&eve_path, &pcap_path, &work_dir).await {
                            Ok(clean_path) => {
                                let duration = start_time.elapsed();
                                info!(
                                    "✅ Filtered in {:.1}s: {}",
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
                                error!("❌ Filter failed in {:.1}s: {}", duration.as_secs_f32(), e);
                            }
                        }
                    }
                    Ok(PipelineMessage::Shutdown) => {
                        info!("🛑 PCAP filter shutting down");
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

    async fn filter_pcap(eve_path: &Path, pcap_path: &Path, work_dir: &Path) -> Result<PathBuf> {
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
            warn!("⚠️ Input PCAP file is empty, creating empty clean PCAP");
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
            warn!("⚠️ No packets found in PCAP file, creating empty clean PCAP");
            // Create an empty but valid PCAP file
            let empty_file = File::create(&clean_path)?;
            let mut empty_writer = PcapWriter::new(empty_file)?;
            drop(empty_writer);
            return Ok(clean_path);
        }

        // Process alerts
        process_alerts(
            eve_path,
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
            info!("🔍 Zeek processor started");

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
                                    "✅ Zeek analysis completed in {:.1}s: {}",
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
                                error!("❌ Zeek failed in {:.1}s: {}", duration.as_secs_f32(), e);
                            }
                        }
                    }
                    Ok(PipelineMessage::Shutdown) => {
                        info!("🛑 Zeek processor shutting down");
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
            warn!("⚠️ PCAP file is empty or too small for Zeek processing");
            // Create an empty conn.log file
            let conn_log_path = zeek_output_dir.join("conn.log");
            std::fs::write(
                &conn_log_path,
                "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n",
            )?;
            return Ok(conn_log_path);
        }

        // Zeek analysis starting (timing handled by caller)

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

        // Check Zeek output (reduced logging)

        let conn_log_path = zeek_output_dir.join("conn.log");
        if !conn_log_path.exists() {
            warn!("⚠️ Zeek didn't generate conn.log (no connections found), creating empty log");
            // Create an empty conn.log with proper headers
            std::fs::write(
                &conn_log_path,
                "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n#close\t2024-01-01-00-00-00\n",
            )?;
        } else {
            // Check if the conn.log actually has connection data (more than just headers)
            let content = std::fs::read_to_string(&conn_log_path)?;
            let data_lines = content
                .lines()
                .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
                .count();

            if data_lines == 0 {
                warn!("⚠️ Zeek generated conn.log but it contains no connection data");
                info!(
                    "📄 conn.log headers only - this indicates no TCP/UDP connections were established"
                );
            } // Connection count reporting handled by caller
        }

        Ok(conn_log_path)
    }

    async fn spawn_ml_client(&self) -> Result<tokio::task::JoinHandle<()>> {
        let ml_rx = self.ml_rx.clone();
        let ml_api = self.config.ml_api.clone();

        let handle = tokio::spawn(async move {
            info!("🤖 ML client started");
            let client = reqwest::Client::new();

            loop {
                match ml_rx.recv() {
                    Ok(PipelineMessage::ConnLogReady(conn_log_path)) => {
                        let start_time = std::time::Instant::now();

                        match NetworkPipeline::call_ml_api(&client, &conn_log_path, &ml_api).await {
                            Ok(response) => {
                                let duration = start_time.elapsed();
                                info!("✅ ML analysis completed in {:.1}s", duration.as_secs_f32());
                                NetworkPipeline::process_ml_response(&response);
                            }
                            Err(e) => {
                                let duration = start_time.elapsed();
                                error!("❌ ML failed in {:.1}s: {}", duration.as_secs_f32(), e);
                            }
                        }
                    }
                    Ok(PipelineMessage::Shutdown) => {
                        info!("🛑 ML client shutting down");
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
            info!("📭 conn.log is empty (no connections), skipping ML analysis");
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

        // Sending connection records to ML API

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
            .filter(|result| result.prediction.confidence > 0.95 && result.prediction.is_malicious)
            .map(|result| ThreatSummary {
                connection: format!(
                    "{}:{} → {}:{}",
                    result.src_ip,
                    result.src_port.map_or("-".to_string(), |p| p.to_string()),
                    result.dst_ip,
                    result.dst_port.map_or("-".to_string(), |p| p.to_string())
                ),
                protocol: result.protocol.clone(),
                threat: result.prediction.class.clone(),
                confidence: (result.prediction.confidence * 100.0).round() as u32,
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
            .filter(|result| result.prediction.is_malicious)
            .collect();

        if !malicious_connections.is_empty() {
            info!(
                "Found {} potentially malicious connections:",
                malicious_connections.len()
            );
            for result in malicious_connections.iter().take(5) {
                // Show first 5
                info!(
                    "  {}:{} → {}:{} [{}] - {} ({:.1}% confidence)",
                    result.src_ip,
                    result.src_port.map_or("-".to_string(), |p| p.to_string()),
                    result.dst_ip,
                    result.dst_port.map_or("-".to_string(), |p| p.to_string()),
                    result.protocol,
                    result.prediction.class,
                    result.prediction.confidence * 100.0
                );
            }
            if malicious_connections.len() > 5 {
                info!("  ... and {} more", malicious_connections.len() - 5);
            }
        }
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
        suricata_config: args.suricata_config,
        zeek_path: args.zeek_path,
        ml_api: args.ml_api,
        capture_duration: Duration::from_secs(args.duration),
        debug: args.debug,
    };

    info!("Starting real-time network analysis pipeline");
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
                    || name.starts_with("suricata_")
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
        info!("🧹 Cleaned up old pipeline files from previous runs");
    }

    // Create work directory if it doesn't exist
    std::fs::create_dir_all(&config.work_dir)?;

    // Initialize file counter (start fresh)
    let counter_file = config.work_dir.join(".file_counter");
    std::fs::write(&counter_file, "0")?;
    info!("🔄 Initialized circular file naming system (1-100)");

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

        // Progress tracking reduced
        packet_number += 1;
    }

    // Packet indexing completed
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
    eve_path: &Path,
    packet_index: &[PacketInfo],
    malicious_packets: &mut HashSet<u64>,
    malicious_flows: &mut HashSet<Flow>,
    filter_log: &mut Vec<FilterLog>,
    mode: &str,
) -> Result<()> {
    let file = File::open(eve_path).context("Failed to open EVE JSON file")?;
    let reader = BufReader::new(file);

    info!("Processing Suricata EVE JSON (streaming)...");
    let mut total_lines: usize = 0;
    let mut alert_lines: usize = 0;
    let mut _non_alert_lines: usize = 0;
    let mut _parse_errors: usize = 0;

    // We'll collect typed Alert entries only for true alert events.
    // But we process them as we go (no big vector load).
    for line_res in reader.lines() {
        total_lines += 1;
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to read line {}: {}", total_lines, e);
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        // Fast early filter: check for "event_type":"alert" or the "alert" key.
        // This avoids trying to deserialize non-alert types.
        // Prefer JSON-based check for correctness.
        let v: Value = match serde_json::from_str(&line) {
            Ok(val) => val,
            Err(e) => {
                _parse_errors += 1;
                error!(
                    "Failed to parse JSON on line {}: {} -- content: {}",
                    total_lines, e, &line
                );
                continue;
            }
        };

        // If it's not an alert event, skip.
        let is_alert = v
            .get("event_type")
            .and_then(|et| et.as_str())
            .map(|s| s.eq_ignore_ascii_case("alert"))
            .unwrap_or(false)
            || v.get("alert").is_some();

        if !is_alert {
            _non_alert_lines += 1;
            // Skipping non-alert event (debug logging reduced)
            continue;
        }

        // Now we have an alert-like object; deserialize into your Alert struct.
        let alert: Alert = match serde_json::from_value(v) {
            Ok(a) => a,
            Err(e) => {
                _parse_errors += 1;
                error!(
                    "Failed to deserialize Alert at line {}: {} -- content: {}",
                    total_lines, e, &line
                );
                continue;
            }
        };

        alert_lines += 1;

        // The rest of your existing logic for each alert:
        // direct mapping by pcap_cnt
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

        // Time-based packet matching (fallback)
        if let Ok(alert_time) = DateTime::parse_from_rfc3339(&alert.timestamp) {
            match_packets_by_time(
                packet_index,
                malicious_packets,
                filter_log,
                &alert,
                alert_time.timestamp() as u32,
            );
        } else {
            // If timestamp parsing fails, you can optionally try other heuristics
            warn!(
                "Could not parse timestamp '{}' for alert (pcap_cnt: {:?})",
                alert.timestamp, alert.pcap_cnt
            );
        }
    }

    if alert_lines > 0 {
        info!(
            "Processed {} alerts from {} EVE events",
            alert_lines, total_lines
        );
    }

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

        // Progress tracking reduced
        packet_number += 1;
    }

    if quarantine_count > 0 {
        info!(
            "Split: {} clean, {} quarantined packets",
            clean_count, quarantine_count
        );
    }

    Ok(())
}

fn write_filter_log(log_path: &Path, filter_log: Vec<FilterLog>) -> Result<()> {
    let file = File::create(log_path)?;
    serde_json::to_writer_pretty(file, &filter_log)?;
    Ok(())
}
