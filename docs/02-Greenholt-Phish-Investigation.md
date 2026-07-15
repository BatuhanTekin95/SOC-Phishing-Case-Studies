# Greenholt Phish Investigation

## Executive Summary

I investigated a phishing email that impersonated Mutawa Marine and used a SWIFT payment theme to deliver a malicious attachment. The email contained a Reply-To address outside the impersonated domain, failed SPF validation, and originated from infrastructure that was not authorized by the domain's published SPF record.

The attachment was presented as a PDF-related financial document, while the filename and file identification results pointed to archive formats. A SHA-256 reputation lookup performed during the lab produced a high malicious detection ratio and associated the sample with LokiBot-related labels.

Based on the combined email, DNS, infrastructure, and file evidence, I classified the message as malicious phishing with high confidence. The available evidence supports delivery of a malicious attachment, but the lab did not include endpoint telemetry proving that the recipient executed it.

## Investigation Scope

| Item | Details |
| --- | --- |
| Scenario | TryHackMe Greenholt Phish training lab |
| Analysis type | Email triage, header review, DNS validation, IOC enrichment, and static file reputation analysis |
| Main tools | Thunderbird, `nslookup`, `dig`, Cisco Talos Intelligence, VirusTotal |
| Primary artifact | Suspicious email and attached archive |
| Verdict | Malicious phishing |
| Confidence | High |

## Evidence Summary

| Evidence | Observation | Assessment |
| --- | --- | --- |
| Sender identity | Visible sender used `mutawamarine.com`; Reply-To used `mail.com` | Strong impersonation indicator |
| Source infrastructure | `192.119.71.157` associated with third-party hosting infrastructure | Does not match the claimed organization's authorized mail path |
| SPF | Published record authorized Microsoft 365; observed source failed SPF | Sending IP was not authorized for the evaluated identity |
| DMARC | Domain published `p=quarantine`; available header showed `dmarc=unknown` | Published policy provides context, but no definitive DMARC result was available in the artifact |
| Attachment | PDF-themed filename, CAB extension, and RAR identification | Strong file masquerading indicator |
| File reputation | 51/64 engines detected the hash during the lab | Strong supporting evidence; reputation is time-dependent |

## Investigation Timeline

1. Reviewed the email body, sender fields, subject, and attachment name.
2. Opened the raw source in Thunderbird and identified the Reply-To, source IP, authentication, and spam-related fields.
3. Enriched the source IP and hostname using Cisco Talos Intelligence.
4. Queried SPF and DMARC DNS records for the impersonated domain.
5. Calculated the attachment SHA-256 hash in an isolated lab.
6. Checked the hash and file-type information using VirusTotal.
7. Correlated all findings and assigned the final verdict.

## Email Triage

<img width="786" height="880" alt="Thunderbird view showing the suspicious sender, external Reply-To address, urgent SWIFT subject, and disguised attachment" src="https://github.com/user-attachments/assets/1433423d-e947-4dbc-b5a4-7bc9778ef19e" />

The message used a financial transfer theme and a reference number to create urgency. The visible sender appeared to be `info@mutawamarine.com`, but replies would be sent to `info.mutawamarine@mail.com`. A different Reply-To can be legitimate, so I treated it as one indicator and correlated it with the remaining evidence.

The attachment name used spacing and the text `.PDF` to appear document-like. The actual filename ended in `.CAB`. This mismatch was a strong reason to avoid opening the file and continue with static analysis.

## Header Analysis

<img width="929" height="867" alt="Thunderbird raw message source highlighting the source IP, hostname, Message-ID, authentication results, and spam score" src="https://github.com/user-attachments/assets/5b7403d5-bb09-46ae-8779-5dd91f2cecac" />

The header showed the source IP `192.119.71.157` and a hostname associated with `hostwindsdns.com`. This infrastructure did not match the Microsoft 365 systems later identified in the domain's SPF record.

The Message-ID included the impersonated domain. This was an inconsistency worth recording, but the artifact alone does not prove who generated or manually inserted the value.

The message also had a negative spam score. That score records how the lab's mail filtering system evaluated the message; it does not show why the filter produced that value. I therefore did not use it as evidence that the attacker deliberately tuned the message to a specific score.

### Header Trust Boundary

Email header values can be supplied or forged before a message reaches the receiving organization's first trusted server. In a production investigation, I would validate the connecting IP against the secure email gateway or message-trace logs. The lab artifact did not provide independent gateway telemetry, so the source-IP conclusion is based on the available header and supporting infrastructure context.

## Infrastructure Enrichment

<img width="1223" height="229" alt="Cisco Talos lookup showing Hostwinds-related hostnames associated with the investigated IP range" src="https://github.com/user-attachments/assets/655a64b3-1620-4ef2-a511-df4ed50b3ffd" />

Cisco Talos data associated hosts in the investigated range with the `hostwindsdns.com` naming pattern. This supported the conclusion that the IP belonged to third-party hosting infrastructure.

Hostwinds is a legitimate provider. Provider ownership does not make an IP malicious, prove that the attacker rented a VPS, or validate every header field. The relevant finding is that the observed infrastructure did not match the claimed sender's authorized email service and was correlated with other phishing indicators.

## SPF Validation

<img width="794" height="182" alt="DNS TXT lookup showing the Mutawa Marine SPF record authorizing Microsoft 365 and ending with minus all" src="https://github.com/user-attachments/assets/d3c65c51-e059-4b9e-8bf8-88a386092cfa" />

I queried the domain's TXT records:

```bash
nslookup -type=txt mutawamarine.com
```

The relevant result was:

```text
v=spf1 include:spf.protection.outlook.com -all
```

This policy authorized the Microsoft 365 SPF include for the evaluated domain. The observed source IP, `192.119.71.157`, was not part of that authorized path, and the available `Authentication-Results` field recorded SPF failure.

The `-all` qualifier means the SPF evaluation should return `fail` for an unmatched sender. It does not, by itself, force every receiving system to reject the message; the final action depends on the receiver's local policy and other controls.

No usable DKIM result was present in the available header data. I therefore could not determine whether a DKIM signature existed or aligned with the visible From domain.

## DMARC Review

<img width="823" height="428" alt="DNS lookup showing the Mutawa Marine DMARC record with a quarantine policy" src="https://github.com/user-attachments/assets/dbf72393-cd4e-4c9f-bdd6-d1eb74ce07a5" />

I queried the DMARC record:

```bash
dig TXT _dmarc.mutawamarine.com
```

The domain published a `p=quarantine` policy. DMARC passes when at least one aligned authentication path passes: aligned SPF or aligned DKIM. A quarantine policy requests suspicious treatment for messages that fail DMARC, but the receiving system still applies its own policy.

The email artifact recorded `dmarc=unknown`, so I could not claim a definitive DMARC fail or use the published policy to explain exactly where the message was delivered. The SPF failure, sender-field mismatch, infrastructure discrepancy, and malicious attachment evidence were sufficient for the final verdict without that assumption.

## Attachment Analysis

The attachment was handled only in an isolated lab. I calculated its hash before performing reputation checks:

```bash
sha256sum <suspicious-file>
```

<img width="925" height="85" alt="Linux terminal showing the SHA-256 calculation for the suspicious attachment" src="https://github.com/user-attachments/assets/726a980f-4190-47e2-b040-554454f4edd7" />

The resulting SHA-256 was:

```text
2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f
```

<img width="1803" height="383" alt="VirusTotal result showing a 51 of 64 malicious detection ratio and archive file identification" src="https://github.com/user-attachments/assets/a7d5a3c9-1de2-4c47-966e-75f8727e2b25" />

At the time of the lab, VirusTotal showed a detection ratio of 51/64. File identification results described the sample as a RAR archive, although the email presented it with a PDF theme and a CAB extension.

The clearest description of the observed layers is:

1. The victim-facing name was designed to look like a PDF document.
2. The visible filename ended with a CAB extension.
3. File identification engines recognized the underlying artifact as a RAR archive.

This mismatch supports masquerading. Reputation labels associated the sample with LokiBot-related detections, but vendor labels can differ and should not be treated as malware-family attribution without deeper static or dynamic analysis.

## Potential Impact

LokiBot is commonly associated with credential and information theft. If the attachment had been executed successfully, possible impact could include stolen browser or email credentials and follow-on access.

No endpoint telemetry was provided in this case. The investigation therefore confirms malicious delivery, not successful execution, credential theft, persistence, or lateral movement.

## Indicators of Compromise

| Type | Indicator | Context and handling |
| --- | --- | --- |
| Source IP | `192.119.71.157` | Investigated sending source; validate current ownership and business impact before blocking |
| Hostname context | `hostwindsdns.com` | Provider-related context; do not block the entire provider domain based on this case |
| Impersonated domain | `mutawamarine.com` | Victim identity, not a malicious domain |
| Reply-To | `info.mutawamarine@mail.com` | Suspicious external reply destination in this message |
| SHA-256 | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` | Strongest file indicator |
| File type | RAR archive presented as CAB/PDF-themed content | Attachment masquerading behavior |
| Reputation label | LokiBot / Trojan.MSIL/Loki | Point-in-time vendor classification |

## MITRE ATT&CK Mapping

| Technique | ID | Evidence | Confidence |
| --- | --- | --- | --- |
| Phishing: Spearphishing Attachment | T1566.001 | Financial-themed phishing email delivered a malicious attachment | High |
| Masquerading: Double File Extension | T1036.007 | PDF-themed filename concealed an archive extension | High |

I did not map Acquire Infrastructure: Virtual Private Server because provider attribution alone does not prove that the adversary rented or acquired the infrastructure. I also did not map execution or credential theft because no endpoint evidence was available.

## Detection and Response Recommendations

### Email Controls

- Search for other messages with the same sender, Reply-To, source IP, subject pattern, or attachment hash.
- Quarantine matching messages and preserve samples for investigation.
- Alert on sender and Reply-To domain mismatches, especially when combined with authentication failure or unusual archives.
- Inspect externally delivered CAB, RAR, and other archive attachments according to business requirements.

### Endpoint and Identity Checks

- Determine whether any recipient opened or extracted the attachment.
- Search for the hash, filename, archive extraction, and child-process activity on recipient hosts.
- Review authentication anomalies and reset exposed credentials if execution is confirmed.
- Isolate affected hosts if malicious execution or command-and-control activity is found.

### IOC Use

- Prefer the exact hash, Reply-To address, and case-specific message attributes over broad provider blocking.
- Add timestamps, source, confidence, and an expiration/review date to operational IOC records.
- Revalidate domain and IP ownership before enforcing a long-term block.

## Limitations

- The investigation used a training artifact rather than production gateway logs.
- No endpoint or identity telemetry was available to prove user execution or compromise.
- The original attachment was assessed through hashing and reputation results; this report does not include full reverse engineering.
- Threat intelligence and detection ratios are point-in-time observations.
- The investigation does not attempt to attribute the activity to a specific threat actor.

## Conclusion

The message was a malicious phishing attempt with high confidence. The strongest evidence was the combination of an external Reply-To address, unauthorized sending infrastructure, SPF failure, deceptive attachment naming, file-type mismatch, and high malicious hash reputation.

The exercise reinforced the value of correlation. None of the hosting, authentication, or reputation findings should be treated as proof in isolation, but together they support a clear and defensible verdict.

## References

- [RFC 7208: Sender Policy Framework](https://www.rfc-editor.org/info/rfc7208)
- [RFC 9989: Domain-based Message Authentication, Reporting, and Conformance](https://www.rfc-editor.org/info/rfc9989)
- [MITRE ATT&CK T1566.001: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1036.007: Double File Extension](https://attack.mitre.org/techniques/T1036/007/)
