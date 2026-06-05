# THM - The Greenholt Phish

## Executive Summary

This report presents a comprehensive investigation of a phishing campaign disguised as a legitimate SWIFT financial transaction notification. The analysis follows a structured incident response methodology, including detailed email header examination, validation of email authentication mechanisms (SPF, DKIM, and DMARC), domain reputation assessment through DNS and WHOIS investigations, and static malware analysis of the attached malicious payload.

This investigation was conducted from the perspective of a SOC analyst, focusing on email triage, threat validation, indicator identification, and initial malware assessment. The case study serves as a practical demonstration of phishing investigation techniques commonly used in Security Operations Centers (SOCs).

The objective of this investigation is to identify indicators of compromise (IOCs), determine the techniques used by the threat actor, and assess the overall legitimacy of the communication. Throughout the analysis, multiple phishing indicators were uncovered, including suspicious sender infrastructure, authentication failures, and malicious file characteristics consistent with credential theft and malware delivery tactics.

The findings demonstrate how attackers leverage trusted financial themes and social engineering techniques to increase the likelihood of user interaction. This case study highlights the importance of email security controls, threat hunting procedures, and analyst-driven investigation techniques in detecting and mitigating phishing threats within an organizational environment.

## Technical Analysis & Incident Investigation

<img width="859" height="865" alt="Ekran görüntüsü 2026-06-05 001210" src="https://github.com/user-attachments/assets/aceb2496-5455-461a-b5c5-b7b385d404d7" />

As shown in the image above, the suspicious email was opened and analyzed using the Thunderbird email client. During the initial triage process, four critical indicators immediately stand out and have been highlighted with red boxes.

First, although the email appears to originate from a legitimate corporate address, info@mutawamarine.com, a closer inspection reveals a significant anomaly in the Reply-To field. If the recipient attempts to respond to the message, the reply is redirected to an external @mail.com address controlled by the attacker rather than the legitimate domain. This technique is commonly observed in phishing campaigns, where threat actors manipulate email headers to impersonate trusted organizations while directing communication to fraudulent accounts. As discussed in the Phishing Fundamentals section, this is a classic example of domain manipulation and sender spoofing.

The subject line is another notable indicator. By using capital letters, a financial theme related to a SWIFT transfer, and a seemingly legitimate reference number (09674321), the attacker attempts to create a sense of urgency and legitimacy. Such social engineering tactics are designed to lower the victim's skepticism and increase the likelihood of interaction.

Finally, the attachment itself exhibits clear signs of malicious intent. The attacker inserted excessive whitespace and included the string “.PDF” within the filename to make the file appear as a harmless PDF document. However, closer examination reveals that the actual file extension is .CAB, a compressed archive format that can be used to deliver and execute malicious content. This technique relies on visual deception, encouraging users to trust and open a potentially dangerous file while concealing its true nature.


<img width="929" height="867" alt="Ctrl u - thunderbird email analysis" src="https://github.com/user-attachments/assets/5b7403d5-bb09-46ae-8779-5dd91f2cecac" />

By examining the technical header fields highlighted in the white boxes above, several indicators of header manipulation and infrastructure abuse become immediately apparent. These artifacts provide valuable insight into the true origin of the email and expose the techniques used by the attacker to disguise the phishing attempt.

One of the most revealing indicators is the exposed source IP address, **192.119.71.157,** along with the associated hostname **hostwindsdns.com.** Rather than originating from the legitimate infrastructure of the organization being impersonated, the message was transmitted through a commercial hosting provider. This discrepancy between the claimed sender identity and the actual sending infrastructure is a strong indicator of phishing activity and suggests that the attacker leveraged rented hosting resources to distribute the malicious email.

Further analysis of the email headers reveals an attempt to create a false sense of legitimacy through the Message-ID field. The attacker manually inserted the impersonated domain name (@mutawamarine.com) into the Message-ID value, likely in an effort to make the email appear authentic to both recipients and automated security systems. While many users never inspect message headers, security analysts recognize that Message-ID values can often reveal inconsistencies between the claimed sender and the actual email source.

Additional evidence can be found in the anti-spam header fields located near the bottom of the message. The X-Spam-Status and X-Spam-Score values appear unusually favorable considering the suspicious characteristics already identified. Under normal circumstances, an email failing SPF (Sender Policy Framework) validation and exhibiting signs of sender impersonation would typically receive a significantly higher spam score or be quarantined by email security controls.

However, in this case, the attacker appears to have carefully crafted both the content and technical attributes of the email to evade detection. As a result, the message received a negative spam score (score = -0.5), allowing it to bypass filtering mechanisms and reach the recipient's inbox. This demonstrates how modern phishing campaigns often combine social engineering with technical evasion techniques to increase delivery success rates and reduce the likelihood of automated detection.


<img width="1223" height="229" alt="cisco" src="https://github.com/user-attachments/assets/655a64b3-1620-4ef2-a511-df4ed50b3ffd" />


To further validate the findings obtained during header analysis, the extracted X-Originating-IP address was investigated using Cisco Talos Intelligence, a widely recognized threat intelligence platform. The results provided additional evidence supporting the conclusion that the email originated from infrastructure unrelated to the organization being impersonated.

During the initial examination of the email headers, we identified the hostname hostwindsdns.com associated with the connecting IP address. While this observation already raised concerns regarding the legitimacy of the sender, it was important to verify the finding through an independent intelligence source. Upon querying the IP address within Cisco Talos Intelligence, the information displayed in the Additional Information section confirmed our earlier observations.

Specifically, the platform's network and IP history data revealed that multiple active hosts within the same IP range were registered under the hostwindsdns.com naming convention, including several subdomains following the hwsrv-* pattern. This correlation provides strong evidence that the infrastructure identified during header analysis is genuine and not the result of header manipulation or misattribution. The consistency between the email artifacts and external threat intelligence data strongly suggests that the phishing campaign was delivered through resources hosted within the Hostwinds network.

It is important to note that Hostwinds itself is a legitimate and reputable commercial hosting provider. The presence of Hostwinds infrastructure should not be interpreted as malicious activity on the part of the company. However, threat actors frequently abuse cloud and hosting services because they offer inexpensive, rapidly deployable infrastructure that can be used to distribute phishing emails, host malicious content, or operate command-and-control systems.

> In many cases, attackers rent short-lived Virtual Private Servers (VPSs) using stolen payment information, fraudulent identities, or temporary accounts. By leveraging third-party hosting providers, threat actors can obscure their true location, complicate attribution efforts, and reduce the likelihood of immediate detection by security controls. This tactic enables malicious infrastructure to be established quickly and discarded just as rapidly once it has served its purpose.


<img width="794" height="182" alt="s" src="https://github.com/user-attachments/assets/d3c65c51-e059-4b9e-8bf8-88a386092cfa" />

To validate whether the sending infrastructure was authorized to transmit email on behalf of the impersonated domain, an SPF (Sender Policy Framework) record check was performed against the domain identified in the Return-Path header: mutawamarine.com.

Using the Linux command:

nslookup -type=txt mutawamarine.com

the domain's DNS TXT records were retrieved and examined. As highlighted in the image above, the official SPF record was returned as:

v=spf1 include:spf.protection.outlook.com -all

This record provides critical information regarding the domain's email authorization policy. Specifically, it indicates that only Microsoft Office 365 mail servers, referenced through spf.protection.outlook.com, are authorized to send email on behalf of mutawamarine.com. Furthermore, the -all qualifier represents a strict enforcement policy, instructing receiving mail servers to reject messages originating from any unauthorized source.

When compared with the findings obtained during header analysis, a clear contradiction emerges. Earlier in the investigation, the true sending source was identified as 192.119.71.157, an IP address associated with the Hostwinds hosting infrastructure rather than Microsoft's Office 365 platform. Since this IP address is not included within the domain's authorized SPF policy, it is not permitted to send email on behalf of mutawamarine.com.

This discrepancy explains why the receiving mail server recorded and SPF validation failure. The sending IP address did not match any of the hosts authorized by the domain's published SPF policy.

By correlating the SPF record, DNS data, and email header artifacts, we can confidently conclude that this email represents a domain spoofing attack. The threat actor attempted to abuse the reputation of a trusted organization while delivering the message through infrastructure that was explicitly unauthorized by the domain owner's published email security policy.


<img width="823" height="428" alt="Ekran görüntüsü 2026-06-05 020652" src="https://github.com/user-attachments/assets/dbf72393-cd4e-4c9f-bdd6-d1eb74ce07a5" />

As part of the investigation, a DMARC record lookup was conducted using the Linux dig command against the impersonated domain, mutawamarine.com. Analyzing published DMARC records helps determine the domain owner's intended response to authentication failures and provides additional evidence when assessing potential domain spoofing attempts. The retrieved policy, highlighted above, offers valuable insight into how suspicious messages should be treated by receiving mail systems.

The most significant element of the record is the p=quarantine policy. This instructs receiving mail servers to treat messages that fail SPF or DKIM validation as suspicious and place them in a Spam or Junk folder rather than delivering them directly to the user's inbox.This finding supports our earlier observations during header analysis, where SPF validation failed.Although the message originated from an unauthorized source, the domain’s DMARC policy specified quarantine rather than rejection for authentication failures. This helps explain why the message was not outright rejected and instead had the potential to reach the recipient’s mailbox depending on the receiving organization’s email security configuration.


<img width="925" height="85" alt="sha256 hash" src="https://github.com/user-attachments/assets/726a980f-4190-47e2-b040-554454f4edd7" />

As the next phase of the investigation, attention shifts from email authentication analysis to the malicious attachment delivered as part of the phishing campaign. To safely examine the artifact, the file was extracted and stored within an isolated laboratory environment, preventing any potential execution or interaction with production systems.

Before performing further malware analysis, a static hash analysis was conducted using the Linux "sha256sum" command. This process generates a unique SHA-256 cryptographic hash value, which serves as a reliable Indicator of Compromise (IOC) for the file. By calculating the hash, analysts can accurately identify the artifact and compare it against records stored in threat intelligence platforms, malware repositories, and security databases.

Establishing the file's hash at an early stage of the investigation enables rapid reputation checks, malware correlation, and threat attribution activities while ensuring that the analysis remains non-invasive and does not require execution of the suspicious file.



<img width="1803" height="383" alt="virustotal analysis" src="https://github.com/user-attachments/assets/a7d5a3c9-1de2-4c47-966e-75f8727e2b25" />

After generating the file hash, the resulting SHA-256 value was submitted to a global threat intelligence platform for reputation analysis. The results provided strong evidence that the attachment is a known malicious artifact rather than a legitimate document.

The most significant indicator is the Detection Score displayed on the report. A score of 51/64 indicates that 51 out of 64 security vendors, including antivirus and endpoint detection solutions, classified the file as malicious. Such a high detection ratio provides strong confidence that the attachment has been previously observed in malicious activity and is widely recognized as a threat within the cybersecurity community.

The file metadata provides additional context regarding the nature of the attachment. The sample has a size of approximately 400.26 KB and was identified by multiple analysis engines as a RAR archive despite being presented to the victim as a PDF-related document. This discrepancy immediately raises suspicion and supports the hypothesis that the file was intentionally disguised to increase the likelihood of user interaction.

## Attachment Structure Analysis

Further examination of the submitted attachment revealed an additional layer of deception. Although the file was initially presented as a CAB archive and visually disguised as a PDF document through filename manipulation, file identification results indicated that the underlying artifact was recognized as a RAR archive.

The use of compressed archive formats is a common technique observed in phishing campaigns. Archive files help attackers conceal malicious payloads, reduce detection rates by email security gateways, and bypass certain content inspection mechanisms. By embedding malicious content within compressed containers, threat actors increase the likelihood that the attachment will successfully reach the victim's inbox.

This layered obfuscation technique demonstrates a deliberate effort to evade both automated security controls and end-user scrutiny. The attacker attempted to exploit the victim's trust by presenting the attachment as a legitimate financial document while concealing its true nature behind multiple file-type disguises.

From an analyst's perspective, the discrepancy between the apparent file extension and the actual file structure serves as a strong indicator of malicious intent and further supports the phishing classification of the email.

The use of multiple file-type disguises demonstrates a layered obfuscation strategy intended to bypass both automated email security controls and human inspection.

## Malware Family Analysis: Loki Malware

Additional intelligence obtained from the reputation analysis identified the sample as belonging to the Trojan.MSIL/Loki malware family. Multiple security vendors associated the file with LokiBot, a well-known information-stealing malware family that has been actively distributed through phishing campaigns for several years.

Loki malware is primarily designed to harvest sensitive information from infected systems and transmit the collected data to attacker-controlled infrastructure. Common targets include:

* Web browser credentials
* Email client credentials
* FTP application credentials
* Cryptocurrency wallet information
* System configuration and user information

Loki is frequently distributed through phishing emails disguised as invoices, financial documents, payment confirmations, and shipping notifications. This delivery method closely aligns with the characteristics observed throughout this investigation, where the attacker impersonated a legitimate organization and leveraged a fraudulent SWIFT transfer notification to entice user interaction.

The Popular Threat Label section further categorizes the sample as a Trojan, Spyware, and Downloader. These classifications suggest that successful execution could result in credential theft, information gathering, and the retrieval of additional malicious payloads from attacker-controlled infrastructure.

Based on the VirusTotal reputation data, file characteristics, and malware classification results, the attachment can be confidently identified as the primary malicious component of the phishing campaign and represents a significant security risk if executed on a victim system.



## Indicators of Compromise (IOCs)

Throughout the investigation, several indicators associated with the phishing campaign were identified and documented. These indicators can be used by security teams for detection, threat hunting, and incident response activities.

| IOC Type            | Indicator                                   |
| ------------------- | ------------------------------------------- |
|Mail Server Hostname | hostwindsdns.com |
| Source IP Address   | 192.119.71.157                              |
| Impersonated Domain | mutawamarine.com                            |
| Malware Family      | LokiBot (Trojan.MSIL/Loki)                  |
| Attachment Type     | RAR Archive (disguised as CAB/PDF document) |
| SHA-256 Hash        |2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f|
| Reply-To Address | info.mutawamarine@mail.com |

These indicators should be incorporated into organizational monitoring and detection systems where appropriate. In particular, the identified hash value can be used to detect the malicious attachment, while the source IP address and associated infrastructure may assist in identifying related phishing activity within the environment.

## MITRE ATT&CK Mapping

The phishing campaign analyzed throughout this investigation exhibits multiple techniques documented within the MITRE ATT&CK framework. The following mappings are based on artifacts observed during email analysis, infrastructure investigation, and malware reputation assessment.

| Technique                                      | ATT&CK ID | Description                                                                                                                                |
| ---------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Phishing: Spearphishing Attachment             | T1566.001 | The threat actor delivered a malicious attachment disguised as a financial SWIFT transaction notification.                                 |
| Masquerading                                   | T1036     | The attachment was designed to appear as a legitimate PDF document through filename manipulation and misleading extensions.                |
| Obfuscated Files or Information                | T1027     | The attacker used multiple file-type disguises and misleading file extensions to conceal the true nature of the malicious attachment and increase the likelihood of user interaction|
| Acquire Infrastructure: Virtual Private Server | T1583.003 | The phishing email originated from infrastructure associated with a commercial hosting provider rather than the impersonated organization. |

These ATT&CK mappings help contextualize the techniques employed by the threat actor and provide a standardized method for describing adversary behavior across security operations, threat hunting, and incident response activities.

## Detection & Mitigation Recommendations

Email Security Controls

* Enforce SPF, DKIM, and DMARC validation to reduce the effectiveness of domain spoofing attacks.
* Configure DMARC policies with monitoring and reporting to identify unauthorized email activity.
* Block or quarantine emails originating from unauthorized infrastructure that fail authentication checks.

Attachment Security

* Restrict or closely inspect compressed archive attachments such as CAB and RAR files received from external senders.
* Implement sandboxing solutions to analyze suspicious attachments before delivery to end users.
* Alert on file extension mismatches and filenames designed to disguise executable content.

Detection Opportunities

* Generate alerts when the Reply-To domain differs from the sender domain.
* Monitor for emails using financial themes, urgent language, and suspicious attachments.
* Add identified IOCs, including the SHA-256 hash, source IP address (192.119.71.157), hostname (hostwindsdns.com), and malicious Reply-To address to organizational detection and blocking systems.

User Awareness

* Educate users to verify unexpected financial notifications and attachments before opening them.
* Train employees to identify common phishing indicators such as spoofed domains, unusual Reply-To addresses, and misleading filenames.

## Investigation Conclusion

Based on the cumulative evidence gathered during the investigation, the analyzed email was conclusively identified as a malicious phishing attempt impersonating Mutawa Marine to deliver malware through a deceptive attachment.

Multiple indicators of malicious activity were identified during the analysis. Header examination revealed inconsistencies between the claimed sender and the actual sending infrastructure, including the use of a Reply-To address controlled by the attacker and an originating IP address associated with third-party hosting services. Further validation of the domain's SPF and DMARC records confirmed that the sending infrastructure was not authorized to transmit email on behalf of the impersonated organization, resulting in authentication failures consistent with domain spoofing activity.

The attachment itself exhibited several characteristics commonly associated with phishing campaigns. The filename was deliberately crafted to resemble a legitimate PDF document while concealing its true nature through misleading extensions and archive-based obfuscation techniques. Reputation analysis of the extracted file identified the sample as a known malicious artifact with strong detection coverage across multiple security vendors.

Threat intelligence analysis identified the payload as a LokiBot variant, a credential-stealing malware family known for targeting web browsers, email clients, FTP applications, and other sources of sensitive information.

Based on the combined findings from email analysis, infrastructure investigation, authentication validation, and malware analysis and reputation assessment, the message should be classified as malicious. The identified indicators of compromise (IOCs) should be incorporated into organizational monitoring, detection, and blocking mechanisms. Additionally, organizations should maintain effective email authentication policies, attachment filtering controls, and user awareness training programs to reduce the risk posed by similar phishing campaigns in the future.


## Lessons Learned

* How to analyze email headers using Thunderbird.
* How SPF, DKIM, and DMARC help identify spoofed emails.
* How DNS records can be leveraged during phishing investigations.
* How to validate suspicious infrastructure using threat intelligence platforms.
* How SHA-256 hashes support malware identification and IOC tracking.
* How phishing campaigns use social engineering and file obfuscation techniques to evade detection.


















