#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_F_CURRENT_CPU},
    helpers::bpf_perf_event_output,
    macros::{map, xdp},
    maps::{PerfEventArray, HashMap, Array},
    programs::XdpContext,
};
use core::mem;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketEvent {
    pub len: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub eth_type: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IpHdr {
    pub ver_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub proto: u8,
    pub check: u16,
    pub src: u32,
    pub dst: u32,
}

// 설정 맵 (Key 0: 0=Disable Filtering(Allow All), 1=Enable Filtering)
#[map]
static FILTER_CONFIG: Array<u8> = Array::with_max_entries(1, 0);

// 프로토콜 필터 맵 (Key: Protocol Number, Value: 1=Allow)
#[map]
static FILTER_PROTOCOLS: HashMap<u8, u8> = HashMap::with_max_entries(10, 0);

#[map]
static FILTER_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(100, 0);

#[map]
static EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

#[xdp]
pub fn xdp_ids(ctx: XdpContext) -> u32 {
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    let len = data_end - data_start;

    // 패킷 파싱 및 필터링
    if !should_capture(&ctx) {
        return xdp_action::XDP_PASS;
    }

    let event: PacketEvent = PacketEvent {
        len: len as u32,
    };

    let flags = ((len as u64) << 32) | BPF_F_CURRENT_CPU as u64;

    unsafe {
        bpf_perf_event_output(
            ctx.ctx as *mut _,
            &EVENTS as *const _ as *mut _,
            flags,
            &event as *const _ as *mut _,
            mem::size_of::<PacketEvent>() as u64,
        );
    }

    xdp_action::XDP_PASS
}

#[inline(always)]
fn should_capture(ctx: &XdpContext) -> bool {
    let data_start = ctx.data();
    let data_end = ctx.data_end();

    // 0. 필터링 활성화 여부 확인 (0: 비활성/전체수집, 1: 활성)
    // 맵 초기값은 0이므로 기본적으로 전체 수집
    let enabled = unsafe { FILTER_CONFIG.get(0) };
    if let Some(enabled) = enabled {
        if *enabled == 0 {
            return true;
        }
    } else {
        return true;
    }

    // 1. Ethernet Header Parsing
    if data_start + mem::size_of::<EthHdr>() > data_end {
        return false;
    }
    let eth = unsafe { &*(data_start as *const EthHdr) };
    
    // IPv4 (0x0800) 확인
    if eth.eth_type != 0x0008 { 
        return false;
    }

    // 2. IPv4 Header Parsing
    let ip_start = data_start + mem::size_of::<EthHdr>();
    if ip_start + mem::size_of::<IpHdr>() > data_end {
        return false;
    }
    let ip = unsafe { &*(ip_start as *const IpHdr) };

    // 3. Protocol Filtering
    let proto_allowed = unsafe { FILTER_PROTOCOLS.get(&ip.proto) };
    if proto_allowed.is_none() {
        return false;
    }

    // 4. Port Filtering
    // TCP(6) or UDP(17)
    if ip.proto == 6 || ip.proto == 17 {
        let trans_start: usize = ip_start + ((ip.ver_ihl & 0x0F) as usize * 4);
        if trans_start + 4 > data_end { 
            return false;
        }
        
        let ports: &[u16; 2] = unsafe { &*(trans_start as *const [u16; 2]) };
        let src_port = ports[0]; 
        let dst_port = ports[1];

        // 0번 포트(Any)가 있으면 허용
        if unsafe { FILTER_PORTS.get(&0) }.is_some() {
            // Pass
        } else {
            // Src 포트가 허용되면 통과
            if unsafe { FILTER_PORTS.get(&src_port) }.is_some() {
                // Pass
            } else {
                // Dst 포트가 허용되면 통과
                if unsafe { FILTER_PORTS.get(&dst_port) }.is_some() {
                    // Pass
                } else {
                    // 모두 해당 없으면 차단
                    return false;
                }
            }
        }
    }

    true
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
