# SIEM-learning-environment
This was a project I created with Claude AI because I wanted a SIEM environment I could learn with in order to expand my knowledge of blue team activities. This turned into something I wanted to polish and share with others.
# HomeSIEM v3 — Personal SOC Training Platform

## Installation
1. Install Python 3.8+
2. In command prompt `pip install flask requests`
3. Double-click `start_siem.bat` (Windows) or run `python siem.py`
4. Browser opens automatically at http://localhost:5001

## What's Included

### 12 Dashboard Tabs
| Tab | Description |
|-----|-------------|
| Dashboard | Live stats, recent alerts, event feed, protocol mix |
| Alerts | Full alert management with filtering and quick-actions |
| Events | Raw packet event stream |
| Logs | Simulated syslog/auth.log/Windows Event logs with search |
| Network Map | Canvas topology map — click hosts to investigate |
| Missions | 15 missions across 3 campaigns (Beginner/Intermediate/Advanced) |
| Simulate | One-click injection of all 10 attack types |
| Rules | 10 detection rules with toggle on/off |
| Wiki | Attack playbooks, port reference, core concepts |
| War Room | 3 timed incident scenarios with SLA pressure |
| Threat Intel | IP block list management |
| Scorecard | XP, levels, accuracy stats, keyboard shortcuts |

### 10 Attack Types
R001 Port Scan · R002 Brute Force · R003 C2 Beacon · R004 Data Exfiltration
R005 Blocked IP · R006 DNS Tunneling · R007 ARP Spoofing · R008 Ransomware
R009 Lateral Movement · R010 Privilege Escalation

### Difficulty Modes
- **Easy** — Attack type shown, hints free, 0.75x XP, 5% false positive rate
- **Normal** — Attack type shown, hints available, 1x XP, 15% FP rate
- **Hard** — Attack type hidden, hints disabled, 1.5x XP, 25% FP rate
- Press `D` to cycle between modes

### Progression System
- 11 levels from Trainee → Elite Defender
- XP from correct/partial/incorrect evaluations
- Streak bonuses every 3 correct in a row
- 15 missions with campaign rewards

### Investigation Features (per alert)
- Threat score ring with contributing factors
- Wireshark-style packet inspector (Frame/Ethernet/IPv4/TCP/Geo)
- Hex dump with colour-coded payload + entropy
- Event timeline from same source IP
- 7-step SOC investigation checklist
- MITRE ATT&CK technique mapping
- Progressive hint system (4 hints per attack type)
- Evaluation with feedback, analyst tip, key indicators
- PCAP export (Wireshark-compatible .pcap files)

### Keyboard Shortcuts
`R` Resolve · `I` Investigating · `F` False Positive · `B` Block IP
`H` Hint · `P` Export PCAP · `Esc` Close modal · `←/→` Navigate alerts · `D` Cycle difficulty

## Learning Path
1. Start on **Easy** mode, work through the Beginner campaign missions
2. Switch to **Normal** for Intermediate campaign  
3. Tackle **Hard** mode for Advanced campaign + War Room scenarios
4. Use the Wiki to study attack playbooks before simulating them
5. Check your Scorecard to track accuracy and identify weak areas
