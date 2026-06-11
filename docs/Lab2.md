# Boogeyman 3

<img width="554" height="133" alt="Ekran görüntüsü 2026-06-10 202405" src="https://github.com/user-attachments/assets/af50f65e-4c82-4f89-9c5f-3e165d0f0327" />


## Introduction


In this lab, I investigated a phishing-related security incident involving Quick Logistics LLC. The threat actor, known as "Boogeyman", had already gained access to the environment through a compromised employee account and remained undetected while waiting for an opportunity to expand the attack.

The next phase of the attack targeted the company's CEO, Evan Hutchinson. A phishing email containing a malicious attachment was delivered to the victim. Although the email appeared suspicious, the attachment was still opened. After noticing that nothing seemed to happen, the user reported the email to the security team for further investigation.

During the initial investigation, the security team discovered the downloaded attachment on the CEO's workstation and determined that the incident most likely occurred between August 29 and August 30, 2023. While this provided an initial lead, the full scope of the compromise was still unclear.

Using Elastic Security, I analyzed the available logs to reconstruct the attack timeline and understand what happened after the attachment was opened. Throughout the investigation, I identified multiple stages of the attack, including credential theft, remote system access, network share enumeration, and lateral movement across several hosts.

The goal of this investigation was not only to analyze the phishing email itself, but also to understand how the attacker used the initial compromise to move through the environment and assess the overall impact of the incident.


<img width="896" height="602" alt="Ekran görüntüsü 2026-06-10 202703" src="https://github.com/user-attachments/assets/83186eb8-9a19-4ca6-9dc0-79c8924f4e99" />


*Phishing email delivered to the CEO using a previously compromised employee account.*


> Throughout this investigation, I used **Elastic Security** as the primary platform for log analysis and threat hunting. Elastic provides a centralized view of security events, allowing analysts to search, correlate, and investigate large volumes of telemetry from multiple data sources. In this lab, it was used to trace the attacker's activities, build a timeline of events, and assess the overall impact of the compromise.

## Initial Analysis

Based on the information provided by the security team, I searched for activity related to the suspicious attachment, `ProjectFinancialSummary_Q3.pdf`, within the estimated incident timeframe.

The search results revealed that the attachment was not a legitimate PDF file. Instead, it launched `mshta.exe`, which subsequently spawned additional processes including `xcopy.exe`, `rundll32.exe`, and PowerShell. This behavior strongly indicated the execution of a malicious HTA payload and marked the beginning of the compromise.


<img width="1567" height="591" alt="Ekran görüntüsü 2026-06-10 205930" src="https://github.com/user-attachments/assets/02a6493f-826a-4b29-8bd6-0be7fb1b0b24" />


*Elastic search results showing the execution chain triggered by the malicious attachment.*

### Process Analysis

To better understand the behavior of the payload, I examined the command-line arguments associated with the processes spawned by `mshta.exe`.

The investigation showed that the HTA file initiated a sequence of actions designed to execute and maintain the malicious payload on the system. First, `xcopy.exe` was used to copy a file named `review.dat` into the user's temporary directory. Shortly afterwards, `rundll32.exe` was executed to load the copied file as a DLL.

Further analysis revealed the use of PowerShell to create a scheduled task that executed `rundll32.exe` with the malicious DLL. This indicated an attempt to establish persistence, allowing the payload to execute automatically on a recurring basis.

The combination of `mshta.exe`, `xcopy.exe`, `rundll32.exe`, and PowerShell is highly suspicious and commonly associated with malware execution chains. At this stage of the investigation, it became clear that the attachment was being used to deploy and maintain a malicious payload on the victim's workstation.

### Persistence Analysis

Further analysis of the PowerShell command line revealed an attempt to establish persistence on the compromised system. The script used the `New-ScheduledTaskAction` and `New-ScheduledTaskTrigger` cmdlets to create a scheduled task that executed `rundll32.exe` with the malicious `review.dat` payload.

By reviewing the full command-line arguments, I identified the name of the scheduled task created by the malware: **Review**.

This persistence mechanism would allow the malicious DLL to be executed automatically on a recurring basis, ensuring that the attacker could maintain access even after the initial infection.

### Network Activity Analysis

After identifying the persistence mechanism, I shifted my focus to network activity generated by the compromised host.

To investigate potential outbound connections, I searched for Sysmon Event ID 3 events, which record network connections initiated by processes on the system.

<img width="541" height="35" alt="Ekran görüntüsü 2026-06-10 215816" src="https://github.com/user-attachments/assets/c0c79f00-46df-4d01-8fd9-49b16ad9ee65" />

The results revealed a connection originating from the compromised workstation (`10.10.155.159`) to the external IP address `165.232.170.151` over TCP port `80`.

<img width="1168" height="101" alt="Ekran görüntüsü 2026-06-10 215900" src="https://github.com/user-attachments/assets/9e1e527b-0bd5-46db-bfab-27ae987b12df" />

This connection was particularly suspicious because it occurred shortly after the execution of the malicious payload. The external destination was likely being used by the malware for command-and-control (C2) communication or to retrieve additional instructions from the attacker.

Identifying this outbound connection provided further evidence that the compromise had progressed beyond initial execution and that the infected host was actively communicating with external infrastructure.

### UAC Bypass Investigation

At this stage of the investigation, it became apparent that the attacker had obtained local administrator privileges on the compromised system. A common next step in such scenarios is to bypass User Account Control (UAC) in order to execute processes with elevated privileges without prompting the user.

To identify the technique used, I searched for several executables commonly associated with UAC bypass techniques, including `fodhelper.exe`, `computerdefaults.exe`, `sdclt.exe`, `eventvwr.exe`, `slui.exe`, `wsreset.exe`, and `cmstp.exe`.

<img width="902" height="33" alt="Ekran görüntüsü 2026-06-10 221425" src="https://github.com/user-attachments/assets/ea9ea40d-7e77-4fdc-9359-5986449b7fbe" />

*Elastic query used to identify executables commonly associated with UAC bypass techniques.*

The investigation revealed the execution of `fodhelper.exe` on the compromised host shortly after the malicious payload established persistence.

<img width="989" height="69" alt="Ekran görüntüsü 2026-06-10 221506" src="https://github.com/user-attachments/assets/4e6bcb04-f636-4a0a-b381-0053dc596491" />

This finding confirmed that the attacker leveraged **fodhelper.exe** to perform a UAC bypass. This technique is frequently abused by threat actors because `fodhelper.exe` is an auto-elevated Windows binary that can be manipulated through registry modifications to launch arbitrary commands with elevated privileges.

The discovery of this activity indicated that the attacker was actively attempting to increase the level of access available on the compromised host and further strengthen their foothold within the environment.

### Credential Dumping Activity

After successfully bypassing UAC, the attacker appeared to shift focus toward credential access.

To identify potential credential dumping activity, I searched for references to GitHub within process command-line arguments. Threat actors frequently use GitHub to host and distribute offensive security tools, making it a useful indicator during investigations.

<img width="260" height="35" alt="Ekran görüntüsü 2026-06-10 222040" src="https://github.com/user-attachments/assets/29e50bcb-8b3a-4591-b2d2-de8498a46206" />

*Query used to identify references to GitHub within process command-line arguments.*

The search results revealed a PowerShell command that downloaded a ZIP archive from a GitHub release page.

<img width="196" height="128" alt="Ekran görüntüsü 2026-06-10 222107" src="https://github.com/user-attachments/assets/69dde305-a34c-40d0-8538-14dcd3e87dbf" />

*PowerShell command used to download Mimikatz from a GitHub release page.*

Further examination of the command line showed that the attacker downloaded **Mimikatz**, a well-known credential dumping tool commonly used to extract plaintext credentials, password hashes, Kerberos tickets, and other authentication material from compromised systems.

The presence of this download strongly suggested that the attacker was preparing to harvest credentials from the compromised host in order to expand access within the environment.


### Credential Discovery

After identifying the download of Mimikatz, I searched for evidence of the tool being executed on the compromised host.

<img width="157" height="36" alt="Ekran görüntüsü 2026-06-11 015455" src="https://github.com/user-attachments/assets/4df56b44-09fb-45a1-a64b-80276f0f9703" />

The results confirmed that `mimikatz.exe` was executed with the `sekurlsa::pth` module, a technique commonly used to perform Pass-the-Hash attacks. This indicated that the attacker had already obtained credential material and was attempting to authenticate using NTLM hashes rather than plaintext passwords.


<img width="676" height="98" alt="Ekran görüntüsü 2026-06-11 015521" src="https://github.com/user-attachments/assets/a2c44584-73dd-4475-bda7-4b7f145accec" />


By examining the command-line arguments associated with the execution of Mimikatz, I identified the credential pair used by the attacker:

**Discovered Credential Pair**

**itadmin:F84769D250EB95EB2D7D8B4A1C5613F2**

The use of Pass-the-Hash demonstrated that the attacker had successfully harvested credentials from the compromised host and was preparing to leverage them for lateral movement to additional systems within the environment.

### File Share Enumeration

After obtaining valid credentials, the attacker began exploring accessible network resources within the environment.

To identify potential file share enumeration activity, I searched for command-line arguments commonly associated with network share access, including references to SMB shares, network paths, and file system operations.

<img width="467" height="38" alt="Ekran görüntüsü 2026-06-11 021543" src="https://github.com/user-attachments/assets/4fef2135-1227-494e-b383-4928159a45f8" />

The search results revealed PowerShell activity interacting with a remote file share hosted on `WKSTN-1327`. The command referenced a script stored within a shared directory:

`\\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1`

<img width="644" height="104" alt="Ekran görüntüsü 2026-06-11 021604" src="https://github.com/user-attachments/assets/50bdedf8-65de-49de-aa69-62e6483be595" />

This finding confirmed that the attacker had successfully accessed a remote share and was actively exploring resources available through the newly acquired credentials. The discovery also provided evidence of lateral movement activity, as the attacker was no longer operating solely on the initially compromised workstation.

### Additional Credential Discovery

After identifying the remote PowerShell script (IT_Automation.ps1), I continued investigating activity related to file access on the compromised host.

To locate references to files and script execution, I searched for PowerShell commands containing file-related activity associated with `WKSTN-0051`.

<img width="477" height="32" alt="Ekran görüntüsü 2026-06-11 024123" src="https://github.com/user-attachments/assets/d573e7fa-b3db-4aa9-b13f-acbe5cf8ccb0" />

The results revealed a command-line event where a PSCredential object was created and credentials were supplied directly within the command. The same event also showed that the credentials were used to execute actions remotely against WKSTN-1327 through Invoke-Command.

<img width="925" height="117" alt="Ekran görüntüsü 2026-06-11 024215" src="https://github.com/user-attachments/assets/f54a5867-81d1-4f27-a1b0-7eec65888400" />

*Command-line event revealing both the embedded credentials and the remote host targeted during the lateral movement attempt.*

By examining the command-line arguments, I identified an additional credential pair embedded within the script:

**QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987**

Further examination of the same event showed that the credentials were being used against WKSTN-1327. This indicated that the attacker had already begun attempting lateral movement using the newly discovered account.

As a result, I identified WKSTN-1327 as the host targeted during the attacker's lateral movement attempt.

### Remote Execution on WKSTN-1327

After identifying `WKSTN-1327` as the target of the lateral movement attempt, I shifted my focus to process creation events on that host.

To investigate activity executed after the remote connection was established, I reviewed Sysmon Event ID 1 logs associated with `WKSTN-1327`.

<img width="815" height="33" alt="2331" src="https://github.com/user-attachments/assets/5ad5db1b-8e65-4648-bbd0-19c4ee320b4c" />

The results revealed the execution of `powershell.exe` with a Base64-encoded command (`-enc`). The process was spawned by `wsmprovhost.exe`, a Windows process commonly associated with PowerShell Remoting and WinRM sessions.

<img width="1506" height="156" alt="324324" src="https://github.com/user-attachments/assets/03b82556-7983-430d-aef7-9d2c824a6634" />

The presence of an encoded PowerShell command strongly suggested that the attacker was executing commands remotely on the host while attempting to conceal the underlying actions from casual inspection.

This activity provided additional evidence that the attacker had successfully leveraged the harvested credentials to execute commands on a remote system and continue the intrusion.

### Encoded PowerShell Analysis

The remote execution event revealed a PowerShell command launched with the `-enc` parameter, indicating that the command had been Base64 encoded.

To understand the attacker's actions, I extracted the encoded string and decoded it using CyberChef. During this process, I first applied the **From Base64** operation and then used **Remove Null Bytes** to clean the output and recover the original PowerShell script.

<img width="1518" height="735" alt="3234" src="https://github.com/user-attachments/assets/e16a9d14-a7f7-4592-b5a7-09f4ef9aa3a2" />

> CyberChef workflow used to decode the Base64-encoded PowerShell command and remove null bytes from the output.


The decoded script revealed a PowerShell-based backdoor designed to communicate with an external server and execute commands received from the attacker. The script leveraged the .NET `WebClient` class to establish communication and retrieve additional instructions.

Further analysis showed references to the URI `/admin/get.php`, suggesting that the malware was configured to contact a remote command-and-control (C2) endpoint. The script also used `IEX` (`Invoke-Expression`) to execute downloaded content directly in memory, a technique commonly used by attackers to avoid writing malicious files to disk.

This finding confirmed that the attacker had successfully established a mechanism for remote command execution and ongoing communication with external infrastructure. The decoded payload also provided valuable insight into the attacker's post-exploitation activity and command-and-control methodology.

### Additional Credential Dumping

After identifying remote execution activity on `WKSTN-1327`, I investigated whether the attacker attempted to harvest additional credentials from the newly compromised host.

To identify credential dumping activity, I searched for Mimikatz execution events on `WKSTN-1327` by reviewing Sysmon Event ID 1 (Process Creation) logs.

<img width="897" height="37" alt="423432" src="https://github.com/user-attachments/assets/a57a9125-400c-4ca6-b3c0-2f07437941c2" />

The results revealed another execution of `mimikatz.exe` using the `sekurlsa::pth` module. Several command-line arguments immediately stood out during the analysis:

* `sekurlsa::pth` – indicating a Pass-the-Hash operation.
* `/user:` – identifying the targeted account.
* `/ntlm:` – containing the NTLM hash associated with the account.

<img width="1533" height="44" alt="Ekran görüntüsü 2026-06-11 112307" src="https://github.com/user-attachments/assets/0704213a-6de6-4dc3-af11-26b9b00e1acd" />

By examining these parameters, I identified the newly dumped credential pair:

**Discovered Credential Pair**

`administrator:00f80f2538dcb54e7adc715c0e7091ec`

This finding demonstrated that the attacker continued harvesting credentials after moving laterally and was leveraging newly acquired hashes to expand access within the environment.


### Domain Controller Access and DCSync Activity

Following the successful compromise of `WKSTN-1327`, I continued investigating the attacker's actions to determine whether access had been expanded further within the environment.

While reviewing process creation events on `WKSTN-1327`, I observed PowerShell activity interacting with `\\DC01.quicklogistics.org\c$`, indicating that the attacker had begun accessing the domain controller.

<img width="1544" height="116" alt="234324323432" src="https://github.com/user-attachments/assets/05bad9c6-e6e2-4c9c-a5a5-16afeb3951eb" />

> PowerShell activity showing access to the administrative share on DC01, identifying the domain controller targeted by the attacker.

This activity allowed me to identify **DC01** as the domain controller within the Quick Logistics environment.

To investigate potential credential theft from Active Directory, I searched for Mimikatz activity associated with the domain controller.

<img width="707" height="30" alt="ads" src="https://github.com/user-attachments/assets/9ea34662-061c-472f-a6d1-078d46389cf6" />

> Elastic query used to identify Mimikatz activity on the domain controller.

The results revealed the execution of Mimikatz using the `lsadump::dcsync` module, a technique that allows attackers to request password hashes directly from Active Directory by impersonating a domain controller.

Several command-line arguments immediately stood out during the analysis:

* `lsadump::dcsync` – indicating a DCSync attack.
* `/domain:quicklogistics.org` – identifying the targeted domain.
* `/user:` – identifying the account being requested from Active Directory.

<img width="1560" height="123" alt="asda" src="https://github.com/user-attachments/assets/acb11f12-2989-4ac2-933e-38d18c2d6d1a" />

> DCSync activity showing the accounts targeted by the attacker on the domain controller.

The attacker initially targeted the `administrator` account. However, further review of the DCSync events revealed an additional request against:

**Discovered Account**

`backupda`

This finding confirmed that the attacker had successfully reached the domain controller and was actively extracting credential material from Active Directory using DCSync techniques. The discovery of the `backupda` account demonstrated that the attacker was expanding beyond standard administrative accounts and targeting additional privileged credentials within the domain.

### Ransomware Download Activity

After obtaining additional credentials from the domain controller, I continued investigating the attacker's post-exploitation activity to determine the next stage of the attack.

To identify potential malware downloads, I searched for PowerShell commands containing the `iwr` (`Invoke-WebRequest`) cmdlet. This cmdlet is commonly used by attackers to download files from remote servers and is frequently observed during malware delivery and post-exploitation activities.

<img width="750" height="34" alt="234324" src="https://github.com/user-attachments/assets/491bb80f-b785-4749-9421-2591423770db" />

> Elastic query used to identify PowerShell download activity on the domain controller.

The search results revealed a PowerShell command that used `Invoke-WebRequest` to download an executable file from an external location:

**Downloaded Payload URL**

`http://ff.sillytechninja.io/ransomboogey.exe`

<img width="1553" height="50" alt="132312" src="https://github.com/user-attachments/assets/e20312ad-8e75-4ae0-884f-1bfa5ba01225" />

> PowerShell command using Invoke-WebRequest to download the ransomware payload from an external server.

The downloaded file was named `ransomboogey.exe`, strongly suggesting that the attacker was preparing to deploy a ransomware payload within the environment.

This finding demonstrated the final stage of the attacker's post-exploitation activity. What initially began as a phishing email had evolved into credential theft, lateral movement, Active Directory compromise, and ultimately the download of a ransomware payload. The investigation highlighted how a single successful phishing attempt enabled the attacker to progressively expand access throughout the environment.




















