# SOC Phishing Case Studies

[![Documentation Check](https://github.com/BatuhanTekin95/SOC-Phishing-Case-Studies/actions/workflows/documentation-check.yml/badge.svg)](https://github.com/BatuhanTekin95/SOC-Phishing-Case-Studies/actions/workflows/documentation-check.yml)

This repository documents my phishing analysis practice from a SOC analyst perspective. It starts with the fundamentals of email investigation and continues with two hands-on cases covering email authentication, IOC enrichment, endpoint telemetry, lateral movement, and Active Directory abuse.

The investigations were completed in controlled training environments. My aim is to show how I move from an initial alert to an evidence-based conclusion, while keeping confirmed observations separate from assumptions.

## Case Studies

| Case study | Focus | Main tools and data | Status |
| --- | --- | --- | --- |
| [Phishing Fundamentals](docs/01-Phishing-Fundamentals.md) | Email flow, headers, authentication, IOC handling, and safe triage | Email headers, DNS, OSINT | Reference guide |
| [Greenholt Phish Investigation](docs/02-Greenholt-Phish-Investigation.md) | Sender impersonation, SPF/DMARC review, infrastructure enrichment, and attachment analysis | Thunderbird, DNS, Cisco Talos, VirusTotal | Completed |
| [Boogeyman3: Phishing to Ransomware Staging](docs/03-Boogeyman3-Phishing-to-Ransomware-Investigation-Elastic-Security.md) | Process chains, persistence, Pass-the-Hash, WinRM, DCSync activity, and payload transfer | Elastic Security, Sysmon, PowerShell, CyberChef | Completed |

## Investigation Approach

I use the following workflow during the case studies:

1. Confirm the scope, affected user, host, and time range.
2. Review the email body, sender identity, headers, links, and attachments.
3. Extract IOCs and enrich them without treating reputation data as proof on its own.
4. Correlate email findings with process, network, authentication, and endpoint telemetry.
5. Map only observed behavior to MITRE ATT&CK and state the confidence of each conclusion.
6. Document containment actions, limitations, and remaining investigation questions.

## Repository Structure

```text
.
├── docs/
│   ├── 01-Phishing-Fundamentals.md
│   ├── 02-Greenholt-Phish-Investigation.md
│   └── 03-Boogeyman3-Phishing-to-Ransomware-Investigation-Elastic-Security.md
├── detections/
│   └── README.md
├── .github/
│   ├── scripts/check_markdown_links.py
│   └── workflows/documentation-check.yml
├── LICENSE
└── README.md
```

## Tools and Data Sources

- Elastic Security and Sysmon telemetry
- Thunderbird and raw email headers
- CyberChef
- VirusTotal
- Cisco Talos Intelligence
- MXToolbox and DNS command-line utilities
- URLScan.io and controlled analysis environments

## Skills Demonstrated

- Phishing email triage and header analysis
- SPF, DKIM, and DMARC interpretation
- IOC extraction and threat intelligence enrichment
- Process and command-line analysis
- Network connection analysis
- Persistence and lateral movement investigation
- MITRE ATT&CK mapping based on observed evidence
- Incident reporting and response recommendations

## Detection Notes

The [detection notes](detections/README.md) contain reusable Elastic KQL examples derived from the Boogeyman3 investigation. Field names may need to be adjusted for a different Elastic integration or ECS mapping.

## Scope and Safety

All credentials, hosts, domains, and malware samples shown in the case studies belong to simulated training scenarios or are presented as historical investigation artifacts. Suspicious files and URLs should only be handled in an isolated lab. IOC reputation can change over time, so indicators should always be validated in context before blocking.

## License

This project is available under the [MIT License](LICENSE).
