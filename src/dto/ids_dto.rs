use chrono::{DateTime, Local, NaiveDateTime};
use libc::uint32_t;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub const TH_FIN: u8 = 0x01;
pub const TH_SYN: u8 = 0x02;
pub const TH_RST: u8 = 0x04;
pub const TH_PUSH: u8 = 0x08;
pub const TH_ACK: u8 = 0x10;
pub const TH_URG: u8 = 0x20;
pub const TH_ECE: u8 = 0x40;
pub const TH_CWR: u8 = 0x80;

pub fn generate_packet_stat_id(
    src_port: u16,
    dst_port: u16,
    src_ip: &str,
    dst_ip: &str,
    received: bool,
) -> String {
    if received {
        format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port)
    } else {
        format!("{}:{}-{}:{}", dst_ip, dst_port, src_ip, src_port)
    }
}

#[derive(Debug, Clone)]
pub struct PcapProcessingInfo {
    pub save_log_dir: String,
    pub save_pcap_dir: String,
    pub save_file_name: String,
    pub read_pcap_file_absolute_path: String,
    pub packet_stats_dict: HashMap<String, PacketStat>,
    pub current_suricata_log_dir: String,
    pub alert_records: Vec<Value>,
    pub etc_records: Vec<Value>,
}

impl PcapProcessingInfo {
    pub fn new(
        save_log_dir: String,
        save_pcap_dir: String,
        save_file_name: String,
        read_pcap_file_absolute_path: String,
        packet_stats_dict: HashMap<String, PacketStat>,
    ) -> Self {
        Self {
            save_log_dir,
            save_pcap_dir,
            save_file_name,
            read_pcap_file_absolute_path,
            packet_stats_dict,
            current_suricata_log_dir: String::new(),
            alert_records: Vec::new(),
            etc_records: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketStat {
    pub xid: u32,
    pub sub_label: u32,
    pub mal: u32,
    pub suricata_event_type: String,
    pub app_proto: String,
    pub master_proto: String,
    pub l4_proto: String,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,

    pub total_packets: u64,
    pub total_bytes: u64,
    pub cwr_count: u32,
    pub ece_count: u32,
    pub urg_count: u32,
    pub ack_count: u32,
    pub psh_count: u32,
    pub rst_count: u32,
    pub syn_count: u32,
    pub fin_count: u32,

    pub s2d_packets: u64,
    pub s2d_bytes: u64,
    pub s2d_goodput_bytes: u64,
    pub s2d_cwr_count: u32,
    pub s2d_ece_count: u32,
    pub s2d_ack_count: u32,
    pub s2d_urg_count: u32,
    pub s2d_psh_count: u32,
    pub s2d_syn_count: u32,
    pub s2d_rst_count: u32,
    pub s2d_fin_count: u32,
    pub c2s_window_size: u32,

    pub d2s_packets: u64,
    pub d2s_bytes: u64,
    pub d2s_goodput_bytes: u64,
    pub d2s_cwr_count: u32,
    pub d2s_ece_count: u32,
    pub d2s_urg_count: u32,
    pub d2s_ack_count: u32,
    pub d2s_psh_count: u32,
    pub d2s_rst_count: u32,
    pub d2s_syn_count: u32,
    pub d2s_fin_count: u32,
    pub s2c_window_size: u32,

    pub alpn_advertised_list: String,
    pub alpn_negotiated: String,
    pub tls_supported_version: String,

    pub certificate_sha1: String,
    pub tls_ssl_version: String,
    pub tls_ssl_server_info: String,
    pub tls_ssl_server_names: String,
    pub quic_version: String,
    pub ja3_client_hash: String,
    pub ja3_client_unsafe_cipher: String,
    pub ja3_server_hash: String,
    pub ja3_server_unsafe_cipher: String,
    pub ja4_client: String,
    pub ja4_client_unsafe_cipher: String,

    pub client_hassh: String,
    pub server_hassh: String,
    pub issuer_dn: String,
    pub subject_dn: String,
    pub esni: String,
    pub esni_cipher: String,
    pub ech_version: String,
    pub is_safari: String,
    pub is_firefox: String,
    pub is_chrome: String,

    pub ssh_tls_server_cipher: String,
    pub ssh_tls_validity: String,

    pub vlan_id: String,
    pub flow_id: String,
    pub entropy_score: String,
    pub multimedia_flow_type: String,
    pub encrypted_proto: String,
    pub fpc_confidence: String,
    pub tunnel_string: String,
    pub dpi_packets: String,
    pub telnet_username: String,
    pub telnet_password: String,
    pub host_server_name: String,
    pub info: String,
    pub mining_currency: String,
    pub geolocation: String,
    pub data_ratio: f64,
    pub stun_mapped_ip_port: String,
    pub stun_peer_ip_port: String,
    pub stun_relayed_ip_port: String,
    pub stun_response_origin_ip_port: String,
    pub stun_other_ip_port: String,
    pub http_url: String,
    pub http_response_status_code: String,
    pub http_request_content_type: String,
    pub content_type: String,
    pub nat_ip: String,
    pub server: String,
    pub user_agent: String,
    pub filename: String,
    pub bittorent_hash: String,
    pub dhcp_fingetprint: String,
    pub dhcp_class_ident: String,
    pub plain_text: String,
    pub payload: String,
    pub payload_interarrival_delay: String,
    pub blacklist: Vec<String>,
}

impl PacketStat {
    pub fn new(
        app_proto: String,
        master_proto: String,
        l4_proto: String,
        first_seen_ms: i64,
        src_ip: String,
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
    ) -> Self {
        Self {
            app_proto,
            master_proto,
            l4_proto,
            first_seen_ms,
            last_seen_ms: first_seen_ms,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            ..Default::default()
        }
    }

    pub fn get_stat_id(&self, received: bool) -> String {
        generate_packet_stat_id(
            self.src_port,
            self.dst_port,
            &self.src_ip,
            &self.dst_ip,
            received,
        )
    }

    pub fn add_packet(
        &mut self,
        received: bool,
        timestamp: i64,
        bytes: u64,
        goodput_bytes: u64,
        tcp_flag: Option<u8>,
    ) {
        self.last_seen_ms = timestamp;
        self.total_packets += 1;
        self.total_bytes += bytes;

        if received {
            self.s2d_packets += 1;
            self.s2d_bytes += bytes;
            self.s2d_goodput_bytes += goodput_bytes;

            if let Some(flag) = tcp_flag {
                self.update_tcp_flags_s2d(flag);
            }
        } else {
            self.d2s_packets += 1;
            self.d2s_bytes += bytes;
            self.d2s_goodput_bytes += goodput_bytes;

            if let Some(flag) = tcp_flag {
                self.update_tcp_flags_d2s(flag);
            }
        }
    }

    fn update_tcp_flags_s2d(&mut self, flag: u8) {
        if flag & TH_CWR != 0 {
            self.cwr_count += 1;
            self.s2d_cwr_count += 1;
        }
        if flag & TH_ECE != 0 {
            self.ece_count += 1;
            self.s2d_ece_count += 1;
        }
        if flag & TH_URG != 0 {
            self.urg_count += 1;
            self.s2d_urg_count += 1;
        }
        if flag & TH_ACK != 0 {
            self.ack_count += 1;
            self.s2d_ack_count += 1;
        }
        if flag & TH_PUSH != 0 {
            self.psh_count += 1;
            self.s2d_psh_count += 1;
        }
        if flag & TH_RST != 0 {
            self.rst_count += 1;
            self.s2d_rst_count += 1;
        }
        if flag & TH_SYN != 0 {
            self.syn_count += 1;
            self.s2d_syn_count += 1;
        }
        if flag & TH_FIN != 0 {
            self.fin_count += 1;
            self.s2d_fin_count += 1;
        }
    }

    fn update_tcp_flags_d2s(&mut self, flag: u8) {
        if flag & TH_CWR != 0 {
            self.cwr_count += 1;
            self.d2s_cwr_count += 1;
        }
        if flag & TH_ECE != 0 {
            self.ece_count += 1;
            self.d2s_ece_count += 1;
        }
        if flag & TH_URG != 0 {
            self.urg_count += 1;
            self.d2s_urg_count += 1;
        }
        if flag & TH_ACK != 0 {
            self.ack_count += 1;
            self.d2s_ack_count += 1;
        }
        if flag & TH_PUSH != 0 {
            self.psh_count += 1;
            self.d2s_psh_count += 1;
        }
        if flag & TH_RST != 0 {
            self.rst_count += 1;
            self.d2s_rst_count += 1;
        }
        if flag & TH_SYN != 0 {
            self.syn_count += 1;
            self.d2s_syn_count += 1;
        }
        if flag & TH_FIN != 0 {
            self.fin_count += 1;
            self.d2s_fin_count += 1;
        }
    }

    fn nanoseconds_to_millisec(&self, nanoseconds: i64) -> f64 {
        nanoseconds as f64 / 1_000_000_000.0
    }

    pub fn print(&self) -> String {
        let start = self.nanoseconds_to_millisec(self.first_seen_ms);
        let end = if self.last_seen_ms != 0 {
            self.nanoseconds_to_millisec(self.last_seen_ms).to_string()
        } else {
            String::new()
        };

        let src = if !self.src_ip.is_empty() && self.src_port != 0 {
            format!("{}:{}", self.src_ip, self.src_port)
        } else {
            String::new()
        };

        let dst = if !self.dst_ip.is_empty() && self.dst_port != 0 {
            format!("{}:{}", self.dst_ip, self.dst_port)
        } else {
            String::new()
        };

        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{:.4}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.mal,
            self.xid,
            self.sub_label,
            self.app_proto,
            self.master_proto,
            self.l4_proto,
            start,
            end,
            src,
            dst,
            self.total_packets,
            self.total_bytes,
            self.s2d_packets,
            self.s2d_bytes,
            self.s2d_goodput_bytes,
            self.d2s_packets,
            self.d2s_bytes,
            self.d2s_goodput_bytes,
            self.cwr_count,
            self.s2d_cwr_count,
            self.d2s_cwr_count,
            self.ece_count,
            self.s2d_ece_count,
            self.d2s_ece_count,
            self.urg_count,
            self.s2d_urg_count,
            self.d2s_urg_count,
            self.ack_count,
            self.s2d_ack_count,
            self.d2s_ack_count,
            self.psh_count,
            self.s2d_psh_count,
            self.d2s_psh_count,
            self.rst_count,
            self.s2d_rst_count,
            self.d2s_rst_count,
            self.syn_count,
            self.s2d_syn_count,
            self.d2s_syn_count,
            self.fin_count,
            self.s2d_fin_count,
            self.d2s_fin_count,
            self.c2s_window_size,
            self.s2c_window_size,
            self.tls_ssl_server_names,
            self.tls_ssl_server_info,
            self.tls_ssl_version,
            self.quic_version,
            self.ja3_client_hash,
            self.ja3_client_unsafe_cipher,
            self.ja3_server_hash,
            self.ja3_server_unsafe_cipher,
            self.ja4_client,
            self.ja4_client_unsafe_cipher,
            self.alpn_advertised_list,
            self.alpn_negotiated,
            self.tls_supported_version,
            self.client_hassh,
            self.server_hassh,
            self.issuer_dn,
            self.subject_dn,
            self.esni,
            self.esni_cipher,
            self.ech_version,
            self.is_safari,
            self.is_firefox,
            self.is_chrome,
            self.ssh_tls_server_cipher,
            self.ssh_tls_validity,
            self.certificate_sha1,
            self.vlan_id,
            self.flow_id,
            self.entropy_score,
            self.multimedia_flow_type,
            self.encrypted_proto,
            self.fpc_confidence,
            self.tunnel_string,
            self.dpi_packets,
            self.telnet_username,
            self.telnet_password,
            self.host_server_name,
            self.info,
            self.mining_currency,
            self.geolocation,
            self.data_ratio,
            self.stun_mapped_ip_port,
            self.stun_peer_ip_port,
            self.stun_relayed_ip_port,
            self.stun_response_origin_ip_port,
            self.stun_other_ip_port,
            self.http_url,
            self.http_response_status_code,
            self.http_request_content_type,
            self.content_type,
            self.nat_ip,
            self.server,
            self.user_agent,
            self.filename,
            self.bittorent_hash,
            self.dhcp_fingetprint,
            self.dhcp_class_ident,
            "",
            "",
            self.payload_interarrival_delay,
            self.blacklist .join(",")
        )
    }

    pub fn log_header() -> &'static str {
        "mal|xCategoryId|category|appProto|masterProto|l4Proto|firstSeenMs|lastSeenMs|\
         srcIp:port|dstIp:port|totalPackets|totalBytes|\
         s2dPackets|s2dBytes|s2dGoodputBytes|\
         d2sPackets|d2sBytes|d2sGoodputBytes|\
         cwrCount|s2dCwrCount|d2sCwrCount|\
         eceCount|s2dEceCount|d2sEceCount|\
         urgCount|s2dUrgCount|d2sUrgCount|\
         ackCount|s2dAckCount|d2sAckCount|\
         pshCount|s2dPshCount|d2sPshCount|\
         rstCount|s2dRstCount|d2sRstCount|\
         synCount|s2dSynCount|d2sSynCount|\
         finCount|s2dFinCount|d2sFinCount|\
         c2sWindowSize|s2cWindowSize|\
         tls/sslServerNames|tls/sslServerInfo|tls/sslVersion|quicVersion|\
         ja3ClientHash|ja3ClientUnsafeCipher|ja3ServerHash|ja3ServerUnsafeCipher|\
         ja4Client|ja4ClientUnsafeCipher|\
         alpnAdvertisedList|alpnNegotiated|\
         tlsSupportedVersion|clientHassh|serverHassh|issuerDn|subjectDn|esni|esniCipher|echVersion|\
         isSafari|isfirefox|isChrome|ssh/tlsServerCipher|ssh/tlsValidity|certificateSha1|vlanId|flowId|entropyScore|\
         MultimediaFlowType|encryptedProto|fpcConfidence|tunnelString|dpiPackets|telnetUsername|telnetPassword|\
         hostServerName|info|miningCurrency|geolocation|dataRatio|stunMappedIp/port|stunPeerIp/port|\
         stunRelayedIp/port|stunResponseOriginIp/port|stunOtherIp/port|httpUrl|httpResponseStautsCode|\
         httpRequestContentType|contentType|natIp|server|userAgent|filename|bittorentHash|dhcpFingetprint|\
         dhcpClassIdent|plainText|payload|payload_interarrival_delay|blacklist"
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketEvent {
    pub len: u32,
}

unsafe impl aya::Pod for PacketEvent {}
