# SOC Phishing Case Studies

## Overview

This repository documents my phishing analysis and incident investigation journey as part of my SOC Analyst training. The project covers phishing fundamentals, email authentication mechanisms, IOC analysis, OSINT techniques, MITRE ATT&CK mapping, and hands-on phishing investigation scenarios.

The repository combines theoretical knowledge with practical investigations performed using industry-standard tools and methodologies. The case studies demonstrate how a phishing attack can evolve from initial access to credential theft, lateral movement, Active Directory compromise, and ransomware deployment.

---

## Objectives

* Analyze phishing emails from a SOC analyst perspective
* Investigate email headers and authentication mechanisms
* Extract and validate Indicators of Compromise (IOCs)
* Perform OSINT and reputation analysis
* Conduct endpoint and log-based investigations
* Map attacker activity to the MITRE ATT&CK framework
* Produce structured incident investigation reports

---

## Repository Contents

### 01 - Phishing Fundamentals

A comprehensive reference guide covering phishing attack methodologies, email delivery protocols, authentication mechanisms (SPF, DKIM, DMARC, and S/MIME), IOC collection, OSINT workflows, threat intelligence resources, SMTP analysis, and MITRE ATT&CK mapping. This section serves as the theoretical foundation for the practical phishing investigations included in this repository.

### 02 - Greenholt Phish Investigation

Investigation of a phishing email involving header analysis, SPF/DMARC validation, IOC extraction, infrastructure analysis, and threat intelligence enrichment.

### 03 - Boogeyman 3: Phishing to Ransomware Investigation

End-to-end incident investigation following a phishing attack that progressed through malware execution, persistence, privilege escalation, credential dumping, lateral movement, Active Directory compromise, DCSync activity, and ransomware staging.

---

## Investigation Methodology

1. Email Triage
2. Header Analysis
3. IOC Extraction
4. Reputation Analysis
5. Endpoint Investigation
6. Threat Hunting
7. MITRE ATT&CK Mapping
8. Incident Reporting

---

## Tools Used

* Elastic Security
* Thunderbird
* CyberChef
* VirusTotal
* MXToolbox
* URLScan.io
* Any.Run
* Linux Terminal
* Cisco Talos Intelligence

---

## Skills Demonstrated

* Phishing Email Analysis
* Email Header Investigation
* SPF, DKIM, and DMARC Validation
* IOC Collection and Enrichment
* OSINT Investigation
* Threat Intelligence Analysis
* Endpoint Investigation
* Process Analysis
* Credential Access Investigation
* Lateral Movement Detection
* MITRE ATT&CK Mapping
* Incident Reporting

---

## Key Outcomes

Through these investigations, I developed practical experience in phishing detection, email forensics, endpoint analysis, credential theft investigations, threat hunting, and incident response workflows commonly used within Security Operations Centers (SOCs).

---

## Disclaimer

This repository is intended for educational and training purposes only. All investigations are performed within controlled lab environments designed for cybersecurity training.
