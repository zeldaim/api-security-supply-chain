# response/ — Wazuh 경보 자동 대응 (Event-Driven Ansible)

Wazuh 경보를 웹훅으로 받아 **Ansible 플레이북으로 대응**합니다. 대응 규칙과 동작이 전부 YAML 코드라 git에 기록이 남습니다(Response-as-Code).
탐지 규칙은 `tools/yara_to_wazuh.py`가 만들고(Detection-as-Code), 배포도 여기 `deploy_rules.yml`이 맡습니다.

> 개인 장비 전용입니다. 팀이나 공용 Wazuh·방화벽은 inventory에 넣지 않습니다.
> 기본 모드는 **notify**(알림·기록만)입니다. 실제 차단은 `response_mode: block`으로 직접 바꿨을 때만 합니다.

```
Wazuh 경보 (level ≥ 7)
  │  wazuh/custom-eda  (integration, Bearer 토큰)
  ▼
ansible-rulebook  rulebooks/wazuh_alerts.yml      ← :5000 웹훅, 같은 IP·규칙은 5분에 한 번 (throttle)
  ├─ level ≥ 12 + 출발지 IP ─▶ playbooks/block_ip.yml
  │        IPv4 확인 → 허용목록이면 skip → notify 모드면 dry-run → block 모드면 nftables 차단(60분 뒤 자동 해제)
  └─ level ≥ 7 ──────────────▶ playbooks/notify.yml
           공통: logs/actions.jsonl 기록 + Slack(SLACK_WEBHOOK_URL 있을 때) + 화면 출력
```

## 파일

| 파일 | 하는 일 |
|---|---|
| `rulebooks/wazuh_alerts.yml` | 웹훅 수신, 조건별로 플레이북 실행 |
| `playbooks/vars/response.yml` | **설정 하나로 관리**: 모드(notify/block), 차단 시간, 허용목록, 기록 경로 |
| `playbooks/block_ip.yml` / `unblock_ip.yml` | 출발지 IP 차단 / 수동 해제 (nftables `inet shadow_resp` 테이블) |
| `playbooks/notify.yml` | 알림·기록만 |
| `playbooks/deploy_rules.yml` | YARA로 만든 Wazuh 규칙 배포. 검사 실패 시 원복하고 재시작 안 함 |
| `playbooks/tasks/record.yml` | 공통 기록·알림 |
| `playbooks/filter_plugins/netcheck.py` | IP 형식·대역 검사 (`is_ipv4`, `ip_in_any`), 외부 패키지 없음 |
| `wazuh/custom-eda(.py)`, `wazuh/ossec_integration.xml` | Wazuh → 웹훅 전달 integration |
| `tests/alerts/*.json`, `tests/send_alert.sh` | Wazuh 없이 흐름을 확인하는 샘플 경보 4종 |
| `inventory/hosts.yml` | 대상 호스트 (`firewall`, `wazuh_manager`) |

## 실행 ① Docker (설치 없이, 검증된 방법)

```bash
cd response && mkdir -p logs && chmod 777 logs
export EDA_WEBHOOK_TOKEN=$(openssl rand -hex 16)      # Wazuh ossec.conf 의 api_key 와 같은 값
docker run -d --name eda --network host -u $(id -u):0 \
  -e HOME=/tmp -e ANSIBLE_COLLECTIONS_PATH=/app/.ansible/collections \
  -e RESPONSE_LOG=/w/response/logs/actions.jsonl -e EDA_WEBHOOK_TOKEN \
  -v "$(cd .. && pwd):/w" -w /w/response \
  quay.io/ansible/ansible-rulebook:latest \
  ansible-rulebook -r rulebooks/wazuh_alerts.yml -i inventory/hosts.yml --env-vars EDA_WEBHOOK_TOKEN -v

bash tests/send_alert.sh                 # 샘플 4개 전송 → 200
cat logs/actions.jsonl                   # 대응 기록
docker logs eda | grep '"msg"'           # 플레이북 출력
docker rm -f eda                         # 끄기
```

> `RESPONSE_LOG`는 **절대 경로**로 줘야 합니다. ansible-rulebook은 `playbooks/` 폴더만 임시 폴더에 복사해서 실행하기 때문입니다. 같은 이유로 설정도 `playbooks/vars/`에 둡니다.

## 실행 ② 직접 설치

```bash
sudo apt install -y openjdk-17-jre-headless python3-venv nftables
python3 -m venv ~/eda && . ~/eda/bin/activate
pip install ansible-core ansible-rulebook
ansible-galaxy collection install ansible.eda
cd response && export RESPONSE_LOG=$PWD/logs/actions.jsonl EDA_WEBHOOK_TOKEN=...
ansible-rulebook -r rulebooks/wazuh_alerts.yml -i inventory/hosts.yml --env-vars EDA_WEBHOOK_TOKEN -v
```

## 손으로 플레이북 돌리기

```bash
ansible-playbook playbooks/notify.yml   -e alert_file=$PWD/tests/alerts/medium_xss.json
ansible-playbook playbooks/block_ip.yml -e alert_file=$PWD/tests/alerts/high_sqli.json                       # dry-run
ansible-playbook playbooks/block_ip.yml -e alert_file=$PWD/tests/alerts/high_sqli.json -e response_mode=block -K
ansible-playbook playbooks/unblock_ip.yml -e ip=203.0.113.50 -K
sudo nft list set inet shadow_resp blocklist                                                                 # 지금 차단 목록
ansible-playbook playbooks/deploy_rules.yml -K --check --diff                                                # 규칙 배포 미리보기
```

## Wazuh 연결 (개인 Wazuh)

```bash
sudo cp wazuh/custom-eda wazuh/custom-eda.py /var/ossec/integrations/
sudo chown root:wazuh /var/ossec/integrations/custom-eda*
sudo chmod 750 /var/ossec/integrations/custom-eda*
# wazuh/ossec_integration.xml 내용을 /var/ossec/etc/ossec.conf 에 넣고 api_key = EDA_WEBHOOK_TOKEN
sudo systemctl restart wazuh-manager
tail -f /var/ossec/logs/integrations.log          # "custom-eda: 전달 100900 → 200"
```

## 검증 기록

**2026-11-09, 개인 VM, Docker `ansible-rulebook 1.2.3` / `ansible-core 2.16`**
- 플레이북 4개 `--syntax-check` 통과
- 토큰이 틀리면 401
- 샘플 경보 결과:
  - SQLi L14 (203.0.113.50) → `dry-run`
  - 경로 조작 L12 (192.168.100.1) → `skip-allowlist`
  - XSS L10 → `notify`
  - L3 → 무시
  - 같은 IP 재전송 → throttle로 무시
- `logs/actions.jsonl` 3줄 기록 확인

**아직 안 한 것**
- ~~`response_mode: block` 실제 차단~~ → soc-lab에서 검증 완료 (`lab/README.md`)
- `deploy_rules.yml` 실제 실행 (soc-lab은 Wazuh가 컨테이너라 `docker cp` 방식 사용 중)
- ~~Wazuh `custom-eda` integration 연결~~ → soc-lab에서 검증 완료

## v4 — 로그 정규화(공통 필드) (2026-11-11)

출처마다 다른 필드(`srcip`/`client_ip`, `url`/`path` …)를 전달 스크립트 한 곳에서 ECS 부분집합(`ecs.source.ip`, `ecs.url.template`, `ecs.user.id` …)으로 맞춘다.
`wazuh/log_schema.py` · `wazuh/custom-eda-v2(.py)` · `wazuh/ossec_integration_v2.xml` · `rulebooks/wazuh_alerts_v4.yml`.
매핑표·검증: [`tests/results/2026-11-11_v4_ecs.md`](tests/results/2026-11-11_v4_ecs.md). v1~v3 파일은 그대로.
