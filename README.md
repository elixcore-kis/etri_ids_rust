# IDS Rust

Rust로 구현된 침입 탐지 시스템 (Intrusion Detection System)입니다. libpcap을 사용하여 패킷을 캡처하고 Suricata와 연동하여 네트워크 트래픽을 분석합니다.

## 기능

- libpcap 기반 실시간 패킷 캡처
- Suricata 연동을 통한 고급 네트워크 분석
- TCP/UDP 프로토콜 통계 수집
- 패킷 및 로그 파일 자동 정리
- BPF 필터 지원

## 프로젝트 구조

```
ids_rust/
├── src/
│   ├── main.rs              # 메인 프로그램
│   ├── config.rs            # 설정 파일 처리
│   ├── dto/
│   │   ├── mod.rs
│   │   └── ids_dto.rs       # 패킷 통계 데이터 구조
│   └── service/
│       ├── mod.rs
│       ├── ids.rs           # 패킷 캡처 및 분석
│       └── suricata.rs      # Suricata 연동
├── config.yaml              # 설정 파일
├── Cargo.toml              # Rust 프로젝트 의존성
└── README.md               # 이 파일
```

## 설정 파일 (config.yaml)

```yaml
file:
  save_root_dir: /data1
  log_period: 7
  pcap_period: 7

interface:
  target: ens19
  filter: tcp

suricata:
  log_dir: /data1/temp_suricata
  rule_dir: /var/lib/suricata/rules
  rule_file_name_list:
    - suricata.rules
    - xa_ids.rules
  config_file_path: /etc/suricata/elixcore_suricata.yaml
```

## 빌드

```bash
cd ids_rust
cargo build --release
```

## 실행 방법

```bash
# 기본 실행 (config.yaml 사용)
sudo ./target/release/ids_rust -c config.yaml

# 특정 인터페이스 지정
sudo ./target/release/ids_rust -c config.yaml -i ens18

# 여러 인터페이스 지정
sudo ./target/release/ids_rust -c config.yaml -i ens18,ens24
```

## 로그 확인

- 로그 파일: `[설정 경로]/log/yyyy/MM/dd/yyyy-MM-ddTHH:mm.log`
  - 예시: `/data1/log/2025/10/08/2025-10-08T13:55.log`
- PCAP 파일: `[설정 경로]/pcap/yyyy/MM/dd/yyyy-MM-ddTHH:mm.pcap`
  - 예시: `/data1/pcap/2025/10/08/2025-10-08T13:55.pcap`

## 의존성

### 시스템 요구사항

- Rust 1.70 이상
- libpcap 개발 라이브러리
- Suricata (선택사항이지만 권장)

### Ubuntu/Debian에서 설치

```bash
sudo apt-get install libpcap-dev suricata
```

### CentOS/RHEL에서 설치

```bash
sudo yum install libpcap-devel suricata
```

## Python 버전과의 차이점

이 Rust 버전은 원래 Python 프로젝트(ids_py_rustrize)를 Rust로 변환한 것입니다. 주요 차이점:

- **성능**: Rust의 메모리 안전성과 성능 최적화를 활용
- **비동기**: tokio를 사용한 비동기 처리로 더 효율적인 멀티태스킹
- **타입 안전성**: 컴파일 타임에 많은 오류를 잡을 수 있음
- **메모리 관리**: 가비지 컬렉션 없이 예측 가능한 성능

## 라이선스

원본 Python 프로젝트의 라이선스를 따릅니다.

## 기여

버그 리포트와 기능 제안은 환영합니다.
