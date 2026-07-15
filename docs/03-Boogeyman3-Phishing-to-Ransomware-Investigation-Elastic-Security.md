# Boogeyman3: Phishing to Ransomware Staging

<img width="554" height="133" alt="Boogeyman3 lab title banner" src="https://github.com/user-attachments/assets/af50f65e-4c82-4f89-9c5f-3e165d0f0327" />

## Executive Summary

I used Elastic Security and Sysmon telemetry to investigate an intrusion at the fictional Quick Logistics LLC environment. The investigation began with a phishing attachment reported by the CEO and developed into a multi-host incident involving malicious HTA execution, scheduled-task persistence, suspicious `fodhelper.exe` activity, Pass-the-Hash, remote PowerShell, DCSync command activity, and the download of a ransomware-named executable.

The evidence confirms that the attacker transferred `ransomboogey.exe` into the environment. The available telemetry does not show encryption activity, ransom-note creation, or the operational impact of the downloaded file. I therefore describe the final stage as ransomware staging rather than confirmed data encryption.

## Lab Scope

| Item | Details |
| --- | --- |
| Scenario | TryHackMe Boogeyman3 training lab |
| Investigation window | 29–30 August 2023 |
| Primary platform | Elastic Security Discover |
| Main telemetry | Sysmon process and network events, PowerShell command lines |
| Initial victim | CEO Evan Hutchinson |
| Initial host | `WKSTN-0051` |
| Lateral movement target | `WKSTN-1327` |
| Domain controller | `DC01` |
| Final observed action | Download of `ransomboogey.exe` |

All credentials and hashes in this report are synthetic lab artifacts. I partially mask them in the written report even though the original lab screenshots may display the complete values.

## Key Findings

| Finding | Evidence level | Assessment |
| --- | --- | --- |
| Phishing attachment triggered an HTA-based process chain | Confirmed | `mshta.exe` was followed by `xcopy.exe`, `rundll32.exe`, and PowerShell activity |
| Scheduled-task persistence | Confirmed | PowerShell created the `Review` task to launch `rundll32.exe` with `review.dat` |
| External HTTP communication | Confirmed connection; purpose assessed | Sysmon recorded traffic to `165.232.170.151:80`; C2 purpose is likely but not proven by network content |
| UAC bypass using `fodhelper.exe` | Consistent with technique | Execution was observed, but the supporting registry hijack was not available |
| Pass-the-Hash | Confirmed command activity | Mimikatz used `sekurlsa::pth` with an NTLM hash |
| WinRM lateral movement | High confidence | `wsmprovhost.exe` spawned encoded PowerShell on `WKSTN-1327` |
| DCSync | Confirmed attempt | `lsadump::dcsync` command activity targeted privileged accounts; successful hash extraction was not independently verified |
| Ransomware payload transfer | Confirmed | PowerShell downloaded `ransomboogey.exe`; file execution and encryption were not shown |

## Investigation Timeline

| Stage | Host | Main observation |
| --- | --- | --- |
| Initial execution | `WKSTN-0051` | PDF-themed attachment associated with `mshta.exe` process chain |
| Payload execution | `WKSTN-0051` | `review.dat` copied and loaded with `rundll32.exe` |
| Persistence | `WKSTN-0051` | Scheduled task named `Review` created |
| Network activity | `WKSTN-0051` | HTTP connection to `165.232.170.151` |
| Privilege escalation attempt | `WKSTN-0051` | Suspicious `fodhelper.exe` execution |
| Tool transfer | `WKSTN-0051` | Mimikatz downloaded from GitHub |
| Alternate authentication | `WKSTN-0051` | `sekurlsa::pth` used with the `itadmin` NTLM hash |
| Credential exposure | `WKSTN-0051` | Plaintext lab credentials found in `IT_Automation.ps1` |
| Lateral movement | `WKSTN-1327` | WinRM/PowerShell Remoting activity and encoded command execution |
| Privileged access activity | `WKSTN-1327` / domain | Pass-the-Hash and DCSync command activity observed |
| Payload staging | Domain environment | `ransomboogey.exe` downloaded with PowerShell |

## Elastic Security Workflow

<img width="1919" height="600" alt="Elastic Security Discover view used to search and correlate endpoint telemetry" src="https://github.com/user-attachments/assets/c8b4e5ac-8fc2-4c05-a8f7-fb5d87a993d3" />

I used Elastic Discover to filter the incident time range, review process relationships, and correlate activity across hosts. The KQL examples below reproduce the investigation logic. Field names may need adjustment if a different Elastic integration or ECS mapping is used.

<img width="896" height="602" alt="Phishing email delivered to the CEO from a previously compromised employee account" src="https://github.com/user-attachments/assets/83186eb8-9a19-4ca6-9dc0-79c8924f4e99" />

The reported attachment was named `ProjectFinancialSummary_Q3.pdf`. The investigation started by searching for this value across process command lines.

## Initial Execution

```kql
process.command_line : "*ProjectFinancialSummary_Q3.pdf*"
```

<img width="1719" height="39" alt="Elastic KQL search for the reported ProjectFinancialSummary Q3 attachment" src="https://github.com/user-attachments/assets/c3569247-dced-424a-8d3f-4b46c191e6d6" />

The results associated the attachment with `mshta.exe`, followed by `xcopy.exe`, `rundll32.exe`, and PowerShell. This process pattern is inconsistent with normal PDF viewing and supports execution of HTA content or a file masquerading as a PDF.

```kql
process.name : ("mshta.exe" or "xcopy.exe" or "rundll32.exe" or "powershell.exe") and
(process.parent.name : "mshta.exe" or process.command_line : "*review.dat*")
```

<img width="1567" height="591" alt="Elastic process events showing mshta, xcopy, rundll32, and PowerShell in the attachment execution chain" src="https://github.com/user-attachments/assets/02a6493f-826a-4b29-8bd6-0be7fb1b0b24" />

`xcopy.exe` copied `review.dat` to a temporary location and `rundll32.exe` loaded the file. PowerShell activity then created a recurring execution mechanism.

## Scheduled-Task Persistence

```kql
process.name : "powershell.exe" and
process.command_line : ("*New-ScheduledTaskAction*" and "*New-ScheduledTaskTrigger*" and "*rundll32*")
```

<img width="1313" height="128" alt="PowerShell command creating the Review scheduled task to run rundll32 with review.dat" src="https://github.com/user-attachments/assets/e4e5bf46-adbc-4215-b7ba-ce21e8aa16c0" />

The command created a scheduled task named `Review` that launched `rundll32.exe` with `review.dat`. The command line directly supports scheduled-task persistence.

## Network Activity

```kql
event.code : "3" and
source.ip : "10.10.155.159" and
destination.ip : "165.232.170.151" and
destination.port : 80
```

<img width="541" height="35" alt="Elastic query for Sysmon network connection Event ID 3" src="https://github.com/user-attachments/assets/c0c79f00-46df-4d01-8fd9-49b16ad9ee65" />

<img width="1168" height="101" alt="Sysmon network event from the compromised workstation to 165.232.170.151 on TCP port 80" src="https://github.com/user-attachments/assets/9e1e527b-0bd5-46db-bfab-27ae987b12df" />

The connection occurred after the malicious process activity. Its timing and destination make command-and-control or follow-on retrieval plausible. Because the lab did not include packet content or a confirmed server response, I record the connection as confirmed and its purpose as an assessment.

## Suspected UAC Bypass

```kql
process.name : (
  "fodhelper.exe" or "computerdefaults.exe" or "sdclt.exe" or
  "eventvwr.exe" or "slui.exe" or "wsreset.exe" or "cmstp.exe"
)
```

<img width="902" height="33" alt="Elastic query for Windows binaries commonly reviewed during UAC bypass investigations" src="https://github.com/user-attachments/assets/ea9ea40d-7e77-4fdc-9359-5986449b7fbe" />

<img width="989" height="69" alt="Process event showing fodhelper.exe execution on the compromised host" src="https://github.com/user-attachments/assets/4e6bcb04-f636-4a0a-b381-0053dc596491" />

`fodhelper.exe` is an auto-elevated Windows binary that can be abused after specific registry values are modified. Its execution in this sequence is suspicious and consistent with a UAC bypass attempt. To confirm the full technique, I would also require the relevant registry modification, parent process, command line, and resulting elevated child process.

## Mimikatz Download

The initial search used GitHub as a lead because the attacker downloaded a tool from a release page. A broad GitHub search can be noisy, so production hunting should add process, user, host, and time context.

```kql
process.name : "powershell.exe" and
process.command_line : ("*github.com*" and ("*Invoke-WebRequest*" or "*iwr*" or "*DownloadFile*"))
```

<img width="260" height="35" alt="Elastic query for PowerShell command lines referencing GitHub" src="https://github.com/user-attachments/assets/29e50bcb-8b3a-4591-b2d2-de8498a46206" />

<img width="196" height="128" alt="PowerShell event showing a Mimikatz archive downloaded from a GitHub release" src="https://github.com/user-attachments/assets/69dde305-a34c-40d0-8538-14dcd3e87dbf" />

The command confirms tool transfer. Downloading Mimikatz indicates credential-access intent but does not, by itself, prove credential dumping succeeded.

## Pass-the-Hash Activity

```kql
process.name : "mimikatz.exe" and process.command_line : "*sekurlsa::pth*"
```

<img width="157" height="36" alt="Elastic query for Mimikatz process execution" src="https://github.com/user-attachments/assets/4df56b44-09fb-45a1-a64b-80276f0f9703" />

<img width="676" height="98" alt="Mimikatz command line using sekurlsa pth with the itadmin account and an NTLM hash" src="https://github.com/user-attachments/assets/a2c44584-73dd-4475-bda7-4b7f145accec" />

The `sekurlsa::pth` module uses existing hash material to create an authentication context. This is Pass-the-Hash, not a command that dumps a new credential.

Masked lab artifact:

```text
itadmin:F84769D2...C5613F2
```

The command proves that the attacker possessed and attempted to use the hash. Authentication logs would provide additional confirmation of which systems accepted it.

## Network Share Access and Credential Exposure

```kql
process.command_line : "*\\\\WKSTN-1327.quicklogistics.org\\ITFiles*"
```

<img width="467" height="38" alt="Elastic query for access to the WKSTN-1327 ITFiles SMB share" src="https://github.com/user-attachments/assets/4fef2135-1227-494e-b383-4928159a45f8" />

<img width="644" height="104" alt="PowerShell command referencing IT Automation script on the WKSTN-1327 network share" src="https://github.com/user-attachments/assets/50bdedf8-65de-49de-aa69-62e6483be595" />

The command accessed:

```text
\\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1
```

This confirms remote-share access and resource discovery. Share access alone does not prove code execution or lateral movement on the remote host.

```kql
host.name : "WKSTN-0051" and process.name : "powershell.exe" and
process.command_line : ("*PSCredential*" and "*Invoke-Command*" and "*WKSTN-1327*")
```

<img width="477" height="32" alt="Elastic query for PowerShell file and remote-command activity on WKSTN-0051" src="https://github.com/user-attachments/assets/d573e7fa-b3db-4aa9-b13f-acbe5cf8ccb0" />

<img width="925" height="117" alt="PowerShell command creating a PSCredential object and targeting WKSTN-1327 with Invoke-Command" src="https://github.com/user-attachments/assets/f54a5867-81d1-4f27-a1b0-7eec65888400" />

The script exposed a plaintext lab credential and used it with `Invoke-Command` against `WKSTN-1327`.

Masked lab artifact:

```text
QUICKLOGISTICS\allan.smith:Tr!c...987
```

This is best mapped as credentials exposed in a file or script. The later process activity on `WKSTN-1327` provides the stronger evidence of successful remote execution.

## WinRM Lateral Movement

```kql
host.name : "WKSTN-1327" and event.code : "1" and
process.parent.name : "wsmprovhost.exe" and process.name : "powershell.exe"
```

<img width="815" height="33" alt="Elastic query for process creation events on WKSTN-1327" src="https://github.com/user-attachments/assets/5ad5db1b-8e65-4648-bbd0-19c4ee320b4c" />

<img width="1506" height="156" alt="Sysmon process event showing encoded PowerShell spawned by wsmprovhost on WKSTN-1327" src="https://github.com/user-attachments/assets/03b82556-7983-430d-aef7-9d2c824a6634" />

`wsmprovhost.exe` is associated with WinRM-hosted PowerShell sessions. Its parent-child relationship with encoded PowerShell on the target host provides high-confidence evidence of remote execution and lateral movement.

## Encoded PowerShell Analysis

Windows PowerShell `-EncodedCommand` commonly represents the command as Base64-encoded UTF-16LE. I decoded the value in CyberChef using **From Base64** followed by **Decode text: UTF-16LE**. Removing null bytes can make the text readable, but selecting the correct character encoding is the more accurate method.

<img width="1518" height="735" alt="CyberChef workflow decoding the Base64 PowerShell command into readable UTF-16LE text" src="https://github.com/user-attachments/assets/e16a9d14-a7f7-4592-b5a7-09f4ef9aa3a2" />

The decoded script used `.NET WebClient`, referenced `/admin/get.php`, and used `IEX` to execute retrieved content in memory. These elements support a PowerShell backdoor assessment and application-layer web communication.

## Additional Pass-the-Hash Activity

```kql
host.name : "WKSTN-1327" and event.code : "1" and
process.name : "mimikatz.exe" and process.command_line : "*sekurlsa::pth*"
```

<img width="897" height="37" alt="Elastic query for Mimikatz execution on WKSTN-1327" src="https://github.com/user-attachments/assets/a57a9125-400c-4ca6-b3c0-2f07437941c2" />

<img width="1533" height="44" alt="Mimikatz sekurlsa pth command using the administrator account and an NTLM hash" src="https://github.com/user-attachments/assets/0704213a-6de6-4dc3-af11-26b9b00e1acd" />

Masked lab artifact:

```text
administrator:00f80f25...e7091ec
```

This event shows another Pass-the-Hash operation. It does not demonstrate that Mimikatz dumped this hash on `WKSTN-1327`; the hash was already supplied as a command argument.

## Domain Controller and DCSync Activity

<img width="1544" height="116" alt="PowerShell activity referencing the DC01 administrative share from WKSTN-1327" src="https://github.com/user-attachments/assets/05bad9c6-e6e2-4c9c-a5a5-16afeb3951eb" />

The command accessed `\\DC01.quicklogistics.org\c$`, identifying `DC01` as the domain controller and showing administrative-share access.

```kql
process.name : "mimikatz.exe" and process.command_line : "*lsadump::dcsync*"
```

<img width="707" height="30" alt="Elastic query for Mimikatz lsadump dcsync command activity" src="https://github.com/user-attachments/assets/9ea34662-061c-472f-a6d1-078d46389cf6" />

<img width="1560" height="123" alt="Mimikatz DCSync command events targeting administrator and backupda accounts" src="https://github.com/user-attachments/assets/acb11f12-2989-4ac2-933e-38d18c2d6d1a" />

The command line used `lsadump::dcsync` against the `quicklogistics.org` domain and targeted `administrator` and `backupda`. DCSync can be initiated remotely by an account with directory replication rights; Mimikatz does not need to execute directly on the domain controller.

Process telemetry confirms the DCSync attempt. To verify successful replication and credential extraction in a production case, I would also review command output, domain controller security telemetry, directory replication activity, and the privileges of the initiating account.

## Ransomware Payload Transfer

```kql
process.name : "powershell.exe" and
process.command_line : (("*Invoke-WebRequest*" or "* iwr *") and "*ransomboogey.exe*")
```

<img width="750" height="34" alt="Elastic query for PowerShell Invoke-WebRequest download activity" src="https://github.com/user-attachments/assets/491bb80f-b785-4749-9421-2591423770db" />

The search found this URL:

```text
hxxp://ff[.]sillytechninja[.]io/ransomboogey.exe
```

<img width="1553" height="50" alt="PowerShell Invoke-WebRequest command downloading ransomboogey.exe" src="https://github.com/user-attachments/assets/e20312ad-8e75-4ae0-884f-1bfa5ba01225" />

The command confirms ingress tool transfer of a ransomware-named executable. The dataset shown in this report does not confirm execution, mass file modification, encryption, extension changes, or ransom-note creation. For that reason, I do not map Data Encrypted for Impact.

## Indicators and Investigation Artifacts

| Type | Value | Context |
| --- | --- | --- |
| External IP | `165.232.170.151` | HTTP destination contacted after payload activity |
| Initial host IP | `10.10.155.159` | Compromised workstation address in the network event |
| Persistence artifact | Scheduled task `Review` | Executes `rundll32.exe` with `review.dat` |
| Payload artifact | `review.dat` | Copied and loaded as a DLL-like payload |
| Remote script | `\\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1` | Contained a plaintext lab credential |
| C2 path | `/admin/get.php` | Found in decoded PowerShell |
| Download URL | `hxxp://ff[.]sillytechninja[.]io/ransomboogey.exe` | Ransomware payload transfer |
| Accounts | `itadmin`, `allan.smith`, `administrator`, `backupda` | Accounts referenced during the incident |

These artifacts belong to the training scenario. They should be validated against time, environment, ownership, and business context before use in a production blocklist.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Malicious attachment delivered to the CEO | High |
| Execution | Signed Binary Proxy Execution: Mshta | T1218.005 | `mshta.exe` associated with the reported attachment | High |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | PowerShell created the recurring `Review` task | High |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP activity and decoded WebClient-based command channel | Medium |
| Privilege Escalation | Abuse Elevation Control Mechanism: Bypass User Account Control | T1548.002 | Suspicious `fodhelper.exe` execution; registry evidence unavailable | Medium |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | Plaintext credential embedded in `IT_Automation.ps1` | High |
| Defense Evasion / Lateral Movement | Use Alternate Authentication Material: Pass the Hash | T1550.002 | Mimikatz `sekurlsa::pth` commands with NTLM hashes | High |
| Discovery | Network Share Discovery | T1135 | Remote `ITFiles` share accessed | High |
| Lateral Movement | Remote Services: Windows Remote Management | T1021.006 | `wsmprovhost.exe` spawned PowerShell on `WKSTN-1327` | High |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell used for persistence, remote execution, and downloads | High |
| Credential Access | OS Credential Dumping: DCSync | T1003.006 | `lsadump::dcsync` command activity against privileged accounts | High for attempt |
| Command and Control | Ingress Tool Transfer | T1105 | Mimikatz archive and `ransomboogey.exe` downloaded | High |

## Containment and Recovery Priorities

1. Isolate `WKSTN-0051` and `WKSTN-1327`; preserve volatile and disk evidence.
2. Block or sinkhole confirmed malicious destinations after checking current ownership.
3. Remove the `Review` task and associated payload only after evidence collection.
4. Reset exposed accounts, terminate active sessions, and invalidate affected authentication material.
5. Review privileged group membership and directory replication rights.
6. If DCSync success is confirmed, follow the organization's domain-compromise recovery process, including controlled `KRBTGT` rotation where appropriate.
7. Hunt for `review.dat`, `rundll32` execution, `wsmprovhost` child processes, Mimikatz indicators, DCSync activity, and the ransomware filename across the environment.
8. Verify backups and search for encryption, ransom notes, and destructive activity before declaring the incident contained.

## Detection Opportunities

- Alert when Office or user-launched content starts `mshta.exe`.
- Correlate `mshta.exe` with `rundll32.exe`, PowerShell, or scheduled-task creation.
- Detect `wsmprovhost.exe` spawning encoded PowerShell on unusual endpoints.
- Alert on Mimikatz module strings such as `sekurlsa::pth` and `lsadump::dcsync`.
- Monitor PowerShell downloads of executable content from newly observed domains.
- Review unusual directory replication requests and accounts granted replication rights.

Reusable examples are available in the repository's [detection notes](../detections/README.md).

## Limitations

- The report is based on a training dataset and the telemetry exposed by the lab.
- Exact event timestamps and complete authentication logs were not included in the written evidence set.
- The UAC bypass assessment lacks the supporting registry event needed for full confirmation.
- DCSync command execution was observed, but successful credential extraction was not independently verified.
- Ransomware download was observed, but execution and data encryption were not.
- The KQL examples reflect common ECS field names and may require adjustment for another integration.

## Conclusion

The investigation shows how one phishing attachment can lead to persistence, credential abuse, remote execution, domain-level credential access attempts, and ransomware staging. The strongest findings are supported by process command lines and host relationships rather than tool names alone.

The most important correction to the initial narrative is the final impact: the data proves that a ransomware-named payload was downloaded, not that files were encrypted. Keeping that distinction clear makes the report more accurate and easier to defend during an interview or incident review.

## References

- [MITRE ATT&CK T1550.002: Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [MITRE ATT&CK T1003.006: DCSync](https://attack.mitre.org/techniques/T1003/006/)
- [MITRE ATT&CK T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [Microsoft: Decode a PowerShell command from a running process](https://learn.microsoft.com/powershell/scripting/samples/decode-powershell-command-from-a-running-process)
