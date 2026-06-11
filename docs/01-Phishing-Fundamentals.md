# Phishing Email Analysis

## Introduction


Phishing attacks remain one of the most common and effective cyber threats targeting individuals and organizations. Attackers use deceptive emails, malicious links, and fraudulent attachments to steal sensitive information, deliver malware, or gain unauthorized access to systems.

This project demonstrates a structured phishing email analysis process from a **Security Operations Center (SOC)** perspective. The objective is to identify **indicators of compromise (IOCs)**, **examine email headers, analyze embedded URLs, inspect attachments, and determine the overall threat level of suspicious emails.**

Throughout this project, various analysis techniques and open-source tools are used to investigate phishing attempts and document findings in a professional incident-response format.

Every phishing email you’ll investigate starts with something simple: an email address. If you don’t understand how it’s structured, you may overlook the very clues attackers rely on.

The anatomy of an email address consists of three main components:

* Username – Identifies the individual user or mailbox owner.
* Symbol (@) – Separates the username from the domain name.
* Domain Name – Identifies the mail server or organization responsible for the email service.

Example: batsource@example.com 

* *Username* - batsource
* *Symbol*- @
* *Domain Name* - example.com

## Email Delivery Protocols

When analyzing how an email travels from an attacker to a victim, it is essential to understand the three core protocols operating behind the scenes:

* *SMTP (Simple Mail Transfer Protocol)*: Responsible for sending emails from a client to a server, or between mail servers. Attackers leverage SMTP servers to push phishing campaigns into the wild.

> {When an email is sent, the sending SMTP server queries the DNS to find the recipient's mail server address, and the DNS responds by returning the recipient's MX (Mail Exchanger) Record so that the message can be correctly routed and later retrieved via POP3 or IMAP}

* *POP3 (Post Office Protocol v3)*: Used for retrieving emails by downloading them to a single local device and typically deleting them from the mail server.

* *IMAP (Internet Message Access Protocol)*: Used for retrieving emails by syncing them across multiple devices while keeping the messages stored on the server.

> Analyst Note: During a phishing investigation, identifying the specific SMTP server or mail relay used by the attacker to launch the email is one of the most critical steps in the digital forensics process. The Received: fields within the email header act as a digital breadcrumb trail, providing us with a chronological map of the entire SMTP traffic from the source to the victim.


​Types of Phishing
--------------

​Attackers use different types of malicious messages depending on their targets and goals:


- **Spam:** Unsolicited bulk emails sent to many people. A more dangerous version that delivers malware is called malspam.
- **Phishing:** Deceptive emails impersonating trusted brands to trick recipients into revealing sensitive data.
- **Spear Phishing:** A highly targeted attack aimed at a specific individual or organization, usually customized with personalized information.
- **Whaling:** A type of spear phishing that specifically targets high-level executives (like CEOs or CFOs) to steal sensitive financial or corporate data.
- **Smishing:** Phishing attacks carried out through SMS text messages on mobile devices.
- **Vishing:** Phishing attacks conducted via voice calls using phone-based social engineering.


​Common Phishing Themes and Tactics (Phishing Emails in Action)
------------

​ **In real-world cyberattacks**, technical manipulation is only half the battle; attackers heavily rely on psychological triggers (social engineering) to force victims into taking action. Based on practical scenarios, the most common phishing themes and attack delivery methods include:

- **Financial and Order Manipulations (Cancel Your Order / Your Recent Purchase):** Attackers send fake invoices or order confirmations for expensive items the victim never bought. This triggers panic, inducing the victim to click malicious links or open attachments to "cancel" the unauthorized transaction.

- **Logistics and Delivery Scams (Track Your Package / Scheduled Shipment):** Exploiting the high volume of daily shipping, these scams impersonate major courier services (e.g., DHL, FedEx). Victims are tricked into resolving a "delivery issue" by downloading malicious tracking files or entering credentials on spoofed tracking portals.

- **Account Status Alerts (Your Account Is on Hold):** This tactic exploits urgency and fear by claiming a critical service (e.g., banking, corporate email, or streaming) is suspended. Victims are rushed into navigating to fake credential harvesting pages in an attempt to recover their accounts.

- **Document-Based Payload Delivery (Download Document Here):** Attackers disguise malware payloads as corporate documents (e.g., PDFs, Excel files with malicious macros, or zipped files). Opening these files directly triggers code execution on the endpoint system.
​

# Threat Actor Psychology

> **Analyst Note:** When conducting phishing analysis, identifying the underlying theme helps determine the sophistication of the threat actor. Mass phishing operations rely on generic "Track Your Package" themes, whereas targeted Spear Phishing campaigns use highly specific corporate themes (like fake HR documents or internal policy updates) to bypass human skepticism.

## Phishing Analysis Tools & Investigation Framework

When a phishing alert is generated within the Security Operations Center (SOC), analysts must perform a structured investigation using trusted Open Source Intelligence (OSINT), threat intelligence, and digital forensics platforms. The objective is to validate Indicators of Compromise (IOCs), identify attacker infrastructure, analyze delivery mechanisms, and map observed behaviors to known adversary Tactics, Techniques, and Procedures (TTPs).

### Email Header Analysis

Email headers contain critical forensic artifacts that reveal the origin, routing path, authentication status, and potential spoofing attempts associated with a phishing campaign.

#### Key Header Analyzers & Utilities

Used to parse raw email headers (.eml, .msg) into a human-readable format. These tools reconstruct SMTP transmission paths, identify anomalies in the Received chain, and validate SPF, DKIM, and DMARC authentication results.

- **MXToolbox:** Performs DNS intelligence gathering, MX record validation, SMTP diagnostics, blacklist checks, and mail server reputation assessments. Particularly useful for identifying malicious mail infrastructure and misconfigured sending hosts.
- **CyberChef:** A versatile forensic utility used to decode Base64 content, analyze encoded payloads, deobfuscate malicious strings, extract hidden indicators, and safely defang suspicious URLs before further investigation.
- **Google Admin Toolbox – Messageheader:** Provides rapid parsing of SMTP headers, visualizes email routing paths, calculates delivery delays, and assists analysts in tracing the exact sequence of mail relay hops.

### Domain & IP Reputation Analysis

Threat actors frequently rotate domains, IP addresses, and hosting providers. Reputation analysis helps determine whether infrastructure has been associated with previous phishing, malware, spam, or command-and-control (C2) activity.

- **VirusTotal:** Aggregates intelligence from numerous antivirus engines, threat feeds, URL scanners, and security vendors. Useful for historical IOC enrichment, reputation validation, and identifying infrastructure previously involved in malicious campaigns.
- **AbuseIPDB:** A community-driven threat intelligence platform used to determine whether an IP address has been reported for phishing, spam distribution, brute-force attacks, scanning activity, or other malicious behavior.
- **Cisco Talos Intelligence:** Provides comprehensive reputation scoring for domains, IPs, and email infrastructure. Analysts can review domain age, passive DNS information, traffic patterns, sender reputation, and historical threat activity.

### URL & Phishing Landing Page Analysis

Embedded URLs often represent the primary attack vector in phishing campaigns. Safe inspection is essential to avoid credential theft, malware infection, or browser exploitation.

- **URLscan.io** A cloud-based reconnaissance and sandbox platform that safely renders suspicious websites. It captures screenshots, records network requests, extracts DOM elements, identifies third-party resources, and uncovers credential harvesting mechanisms.

- **Browserling / Wannabe1337** Provides isolated browser environments for controlled interaction with suspicious websites. Useful for investigating conditional redirects, JavaScript-based payload delivery, geo-targeted phishing pages, and anti-analysis techniques.

### File & Attachment Analysis

Malicious attachments frequently serve as the initial execution vector for malware deployment, credential theft, ransomware delivery, or remote access trojans (RATs).

- **Any.Run** An interactive malware analysis sandbox that enables analysts to observe file execution in real time. It reveals process trees, network communications, registry modifications, persistence mechanisms, dropped files, and attacker infrastructure.

- **Hybrid Analysis** An automated malware analysis platform that combines static and dynamic analysis techniques to generate detailed forensic reports, extract IOCs, identify malware families, and correlate behaviors with the MITRE ATT&CK framework.

- **Joe Sandbox** Provides enterprise-grade malware detonation and behavioral analysis. Generates extensive reports covering execution flow, memory artifacts, persistence techniques, anti-VM checks, privilege escalation attempts, and ATT&CK technique mapping.


## IOC Collection & Correlation

During the investigation, analysts should continuously extract and validate key Indicators of Compromise (IOCs):

- **Network Indicators:** Sender IP addresses, Reply-To domains, Embedded URLs, and Domain registrations.
- **File Artifacts:** File hashes (MD5, SHA1, SHA256) from suspicious attachments.
- **Email Authentication & Identity:** Authentication results (SPF, DKIM, DMARC), usernames, email addresses, and credential harvesting artifacts.

Collected IOCs should be correlated with threat intelligence feeds to identify known phishing campaigns, adversary infrastructure, and related malicious activity.

### IOC Example

The following example demonstrates the types of Indicators of Compromise (IOCs) that SOC analysts commonly collect during a phishing investigation. These artifacts can be used for threat hunting, detection engineering, and incident response activities.

| IOC Type          | Example                                                               |
| ----------------- | --------------------------------------------------------------------- |
| Sender Email      | [attacker@example.com](mailto:attacker@example.com)                   |
| Reply-To Address  | [support-verification@mail.com](mailto:support-verification@mail.com) |
| Source IP Address | 192.0.2.10                                                            |
| Domain            | malicious-example.com                                                 |
| URL               | hxxp://malicious-example[.]com/login                                  |
| SHA-256 Hash      | a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef      |
| Malware Family    | Information Stealer                                                   |
| Attachment Name   | Invoice_2025.pdf.exe                                                  |

> **Analyst Note:** Individual IOCs rarely provide sufficient evidence on their own. Effective phishing investigations rely on correlating multiple indicators, such as sender infrastructure, authentication results, URLs, file hashes, and attachment characteristics, to determine whether an email represents a genuine threat.


## Operational Security (OPSEC) Notice

- **NEVER** interact directly with suspicious URLs, attachments, or phishing emails from a production workstation or corporate network.
- **Always** perform analysis within isolated environments such as sandboxes, virtual machines, or cloud-based detonation platforms. 

Failure to maintain proper operational security can result in:
- Accidental malware execution
- Credential compromise
- Session token theft
- Browser exploitation
- Internal network exposure
- Threat actor detection of investigative activity

Using controlled analysis environments significantly reduces risk while preserving forensic integrity.

## MITRE ATT&CK Mapping

Common ATT&CK techniques observed during phishing investigations include the following. Mapping phishing-related activity to the MITRE ATT&CK framework helps analysts understand how an attack progresses beyond the initial email and provides a standardized method for describing adversary behavior.

| Technique | ATT&CK ID |
|------------|------------|
| Phishing | T1566 |
| Spearphishing Attachment | T1566.001 |
| Spearphishing Link | T1566.002 |
| User Execution | T1204 |
| Command and Scripting Interpreter | T1059 |

>**Analyst Note on MITRE ATT&CK Framework:**
>MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-accessible, structured knowledge base of adversary tactics and techniques based on real-world observations. Because threat actors constantly evolve their methods, tools, and bypass capabilities, **the MITRE ATT&CK framework is not static; it is continuously updated to reflect the shifting cyber threat landscape.**
>
>As SOC analysts, mapping phishing indicators to the MITRE ATT&CK framework allows us to move beyond identifying the initial phishing email and better understand the potential stages that may follow.
>
>This approach helps analysts anticipate attacker behavior, improve detection capabilities, and conduct more effective incident response activities.

## Email Authentication, Delivery Controls & SMTP Analysis

Email authentication technologies form the foundation of modern phishing defense. They help receiving mail servers verify sender legitimacy, detect domain spoofing attempts, and enforce security policies before messages reach end users.

For SOC Analysts, validating email authentication results is one of the most important steps during phishing triage and incident response.

### SPF (Sender Policy Framework)

* **Purpose** IP-based sender authorization.

* **How It Works** SPF allows domain owners to publish a DNS TXT record that explicitly defines which mail servers are authorized to send email on behalf of their domain. When an email is received, the destination mail server compares the source SMTP IP address against the SPF record published in DNS.

* **Validation Outcomes:**

* **Pass** → Sending IP is authorized.
* **Fail** → Sending IP is not authorized.
* **SoftFail** → Potentially unauthorized sender.
* **Neutral** → No explicit policy defined.
* **None** → SPF record not present.
* **Security Value** → SPF helps prevent direct domain spoofing attacks where threat actors attempt to impersonate legitimate organizations by sending mail from unauthorized infrastructure.

### DKIM (DomainKeys Identified Mail)

* **Purpose** Cryptographic message integrity and sender authentication.

* **How It Works** DKIM digitally signs selected email headers and message content using a private cryptographic key controlled by the sending domain. The receiving mail server retrieves the corresponding public key from DNS and validates the signature.

* **This process confirms:**

* The message originated from the claimed domain.
* Email content was not modified during transit.
* Message headers remain intact.
* **Security Value:** Prevents email tampering and ensures that the message genuinely links back to the sender's domain, making it harder for attackers to spoof specific brand headers.

Even if an email traverses multiple mail relays, DKIM helps ensure message authenticity and integrity throughout delivery.

### DMARC (Domain-based Message Authentication, Reporting & Conformance)

* **Purpose** Policy enforcement, domain protection, and reporting.

* **How It Works** DMARC builds upon SPF and DKIM by instructing receiving mail systems how to handle authentication failures. A domain owner publishes a DMARC policy in DNS that specifies the enforcement action.

* **DMARC Policies**

 * **p=none** Monitoring mode.Collect authentication reports.No enforcement action.Emails are still delivered.

 * **p=quarantine** Suspicious message handling.Messages failing authentication are sent to Spam/Junk folders.Reduces successful phishing delivery.

 * **p=reject** Strict enforcement. Messages failing authentication are rejected during SMTP delivery.Prevents spoofed emails from reaching users.

* **Security Value:** DMARC is widely considered the most effective defense against domain impersonation and business email compromise (BEC) attacks when properly configured and enforced.

### S/MIME (Secure/Multipurpose Internet Mail Extensions)
* **Purpose** End-to-end encryption and user identity verification.

* **How It Works** Unlike SPF, DKIM, and DMARC—which operate at the mail server level—S/MIME uses individual user certificates.

* **Each user possesses a cryptographic certificate capable of:**

* Digitally signing messages
* Encrypting email content
* Verifying sender identity
* Security Value

* **S/MIME provides:**

* Confidentiality
* Message integrity
* Non-repudiation
* User-level identity assurance

> **Value:** This makes it particularly valuable for executive communications, legal correspondence, healthcare, and financial sectors.

## SOC Analyst Validation Checklist

During phishing investigations, analysts should always review the following header fields:

* **Authentication-Results:** Contains the ultimate verdict of SPF, DKIM, and DMARC checks.

* **ARC-Authentication-Results:** Useful if the email was forwarded; preserves the original authentication state.

* **Received-SPF:** Shows the raw SPF validation result and the sending gateway IP.

* **DKIM-Signature:** Contains the cryptographic signature data used for verification.

* **Return-Path:** The envelope From address where bounce messages are sent.

* **From:** The visible sender address displayed to the end user.

* **Reply-To:** The address where user responses will actually be sent.

* **Received:** Tracks the hop-by-hop routing path of the email across mail servers.

### Key questions:

* Did SPF pass?

* Did DKIM pass?

* Is DMARC aligned?

* Does Return-Path match the sender domain?

* Is Reply-To different from the visible sender?

* Are there signs of forwarding abuse?

* Is the sender using a lookalike domain?

---

## Common Authentication Bypass Techniques

Threat actors rarely rely solely on traditional spoofing. Modern phishing campaigns often exploit authentication gaps through various sophisticated techniques.

### Weak DMARC Enforcement

Organizations operating with a loose policy (e.g., p=none) are only monitoring authentication failures rather than actively blocking them.

* *Impact:* DMARC failures are logged, but malicious messages may still successfully reach user inboxes, leading to increased phishing exposure.

### 2. Lookalike Domains (Typosquatting)
Attackers register visually similar domains and configure legitimate SPF, DKIM, and DMARC records for them to bypass structural filters.

* *Examples:*
  * microsoft.com $\rightarrow$ micr0soft.com
  * paypal.com $\rightarrow$ paypa1.com
* *Outcome:* 
  * SPF = Pass | DKIM = Pass | DMARC = Pass
  * Despite passing all cryptographic authentication checks, the domain itself is fraudulent and the email remains malicious.


### Display Name Spoofing

This technique targets human psychology rather than technical controls. The email architecture hides the actual source behind a trusted name.

* *Example:* 
  * *Visible Name:* CEO Name
  * *Actual Source:* <attacker@gmail.com>
* *Outcome:* The visible display name appears completely trustworthy to the end-user, while the underlying email address belongs entirely to the attacker.

---

### SMTP Response Codes & Email Delivery Analysis

SMTP status codes provide critical visibility into how mail servers process and respond to email transactions. Understanding these codes is essential when investigating phishing delivery attempts, authentication failures, and mail routing issues.


### Common SMTP Response Codes

| Code | Meaning | Description / Security Relevance |
| :--- | :--- | :--- |
| *220* | Service Ready | Server is ready to start the SMTP session. |
| *221* | Service Closing Connection | The transmission channel is closing. |
| *235* | Authentication Successful | Client successfully authenticated with the server. |
| *250* | Requested Action Completed | Mail delivery/transfer was successful. |
| *421* | Service Temporarily Unavailable | Server is shutting down or transmission channel is closing. |
| *450* | Mailbox Temporarily Unavailable | Local mailbox is busy or locked; retry later. |
| *451* | Local Processing Error | Server aborted the action due to a local server error. |
| *452* | Insufficient Storage | Server has run out of storage space temporarily. |
| *550* | Mailbox Unavailable / Message Rejected | The target mailbox does not exist or the policy blocked it. |
| *551* | User Not Local | Server refuses to relay messages for non-local accounts. |
| *552* | Mailbox Storage Exceeded | The recipient's inbox is full. |
| *553* | Invalid Recipient | Requested action not taken; mailbox name not allowed. |
| *554* | Transaction Failed | Generic permanent failure; connection or message rejected. |

### Where Can Analysts Observe SMTP Response Codes?

#### Mail Server & Secure Email Gateway (SEG) Logs

This is the most authoritative source for delivery analysis.

* *Enterprise SEGs & Mail Gateways:* Microsoft Exchange, Postfix, Sendmail, Proofpoint, Cisco Secure Email, Microsoft Defender for Office 365.

  
* *Typical SIEM Platforms:* Splunk, Elastic, Microsoft Sentinel, QRadar.

*What these logs reveal:*

* Inbound/Outbound delivery attempts.
* Cryptographic authentication results (SPF, DKIM, DMARC statuses).
* Detailed SMTP negotiation handshakes.
* Gateway enforcement actions (Quarantined, Blocked, Delivered).
* Detection and mitigation of coordinated phishing campaigns.

#### Non-Delivery Reports (NDRs)

Also known as:
*Bounce Messages* or *Delivery Status Notifications (DSNs)*.

* *Trigger:* Generated automatically by mail transfer agents (MTAs) when a message delivery permanently or temporarily fails.
* *Analysis Value:* NDRs often contain detailed diagnostic information, system bounce codes, and the original transmission headers that help analysts understand precisely why a message was rejected.

##### Example NDR Failures:

```text
550 5.7.26 Message rejected due to DMARC policy
554 Transaction Failed - Sender Reputation Block
```

NDRs often contain detailed diagnostic information that can help analysts understand why a message was rejected.

##### Raw Email Headers

When a phishing email reaches a user's mailbox, SMTP sessions are no longer visible. However, their forensic footprint remains embedded within the email metadata.

##### Analysts Should Inspect:

* *Received:* Traces the routing path and originating IP.
* *Authentication-Results:* Displays SPF, DKIM, and DMARC alignment verdicts.
* *X-Forefront-Antispam-Report:* Contains Exchange-specific spam confidence levels (SCL).
* *Diagnostic-Code:* Provides the explicit reason code returned by the receiving gateway.
* *X-MS-Exchange-Organization:* Internal policy and routing identifiers.

#### Examples

* *Hop-by-Hop Routing Artifact:*
  Received: from mail.example.com with ESMTPS id ABC123 (250 OK)

* *Authentication Failure Diagnostic:*
  Diagnostic-Code: smtp; 550 5.7.1 Unauthenticated email prohibited by policy

These artifacts provide insight into the delivery path and enforcement decisions made by intermediate mail systems.

Analyst Lab Validation (Controlled Environment)

Security teams frequently validate email defenses by manually interacting with SMTP services in isolated laboratory environments.

#### This allows analysts to observe:

* **SMTP handshakes**
* **Banner information**
* **Authentication responses**
* **Relay restrictions**
* **Delivery controls**

#### Typical observations include:

* 220 Service Ready
* 250 OK
* 550 Rejected
* 554 Transaction Failed

These responses help verify security controls, troubleshoot mail flow issues
and understand how external mail infrastructure enforces authentication and reputation policies.

# Conclusion

This project provided a practical introduction to phishing email analysis from a SOC Analyst perspective. Through the examination of email protocols, authentication mechanisms, header artifacts, indicators of compromise (IOCs), and threat intelligence resources, I developed a structured approach to identifying and investigating phishing attempts.

The research and analysis performed throughout this project highlighted how attackers combine technical techniques with social engineering to increase the effectiveness of their campaigns. Understanding email authentication controls such as SPF, DKIM, and DMARC, along with proper header analysis and IOC validation, is essential for distinguishing legitimate communications from malicious ones.

By documenting investigation methodologies, analysis tools, and real-world phishing concepts, this repository serves as both a learning resource and a demonstration of practical security analysis skills. It reflects my growing understanding of email security, threat intelligence, digital forensics, and incident response processes commonly used within Security Operations Centers (SOCs).

As phishing remains one of the most prevalent initial access techniques used by threat actors, developing strong analytical and investigative skills is critical for effective detection and response. This project represents an important step in my cybersecurity journey and provides a foundation for further exploration of threat hunting, malware analysis, and incident response.

> To complement this theoretical foundation with practical experience, the subsequent sections of this repository document step-by-step walk-throughs and hands-on case studies conducted in simulated laboratory environments.

