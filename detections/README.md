# Detection Notes

These queries turn the main Boogeyman3 findings into reusable hunting ideas. They are starting points, not production-ready rules. I would first confirm the local Elastic integration, field mapping, normal administrative activity, and expected false positives.

The examples use common Elastic Common Schema fields. Sysmon data may use `event.code`, `winlog.event_id`, or integration-specific fields depending on the pipeline.

## Suspicious Mshta Process Chain

```kql
process.name : "mshta.exe" or
process.parent.name : "mshta.exe" or
(process.name : ("rundll32.exe" or "powershell.exe") and process.command_line : "*review.dat*")
```

**Why it matters:** `mshta.exe` is uncommon in many environments and can execute script content. Parent-child relationships and command lines make the result more useful than alerting on the binary alone.

**Tuning:** Exclude known software deployment or internal application workflows only after validating their signer, path, parent, user, and command line.

## PowerShell Scheduled-Task Creation

```kql
process.name : "powershell.exe" and
process.command_line : ("*New-ScheduledTaskAction*" and "*New-ScheduledTaskTrigger*") and
process.command_line : ("*rundll32*" or "*.dat*")
```

**Why it matters:** This combination detects scripted persistence similar to the `Review` task created in the lab.

**Tuning:** Compare task name, executable path, user context, and endpoint role with approved automation.

## Fodhelper in a Suspicious Context

```kql
process.name : "fodhelper.exe" and
not process.parent.name : "explorer.exe"
```

Follow-up hunting should include registry changes under:

```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

**Why it matters:** `fodhelper.exe` is auto-elevated and can be abused after a registry hijack.

**Important:** Execution alone does not confirm UAC bypass. Correlate the registry write, parent process, command line, integrity level, and elevated child process.

## Mimikatz Pass-the-Hash Command

```kql
process.command_line : ("*sekurlsa::pth*" or "*/ntlm:*")
```

**Why it matters:** The `sekurlsa::pth` string is strongly associated with Mimikatz Pass-the-Hash usage.

**Follow-up:** Review the supplied account, source host, logon events, target systems, and whether the hash was accepted.

## WinRM with Encoded PowerShell

```kql
process.parent.name : "wsmprovhost.exe" and
process.name : "powershell.exe" and
process.command_line : ("*-enc*" or "*-EncodedCommand*")
```

**Why it matters:** `wsmprovhost.exe` spawning encoded PowerShell can indicate remote execution through WinRM.

**Tuning:** Administrators and management tools may use WinRM legitimately. Baseline approved source hosts, service accounts, scripts, and change windows.

## DCSync Command Activity

```kql
process.command_line : ("*lsadump::dcsync*" or "*dcsync*")
```

**Why it matters:** The command indicates an attempt to request directory replication data for credential access.

**Follow-up:** Review domain controller telemetry, directory replication events, initiating account privileges, target accounts, and unusual replication-right assignments.

## PowerShell Executable Download

```kql
process.name : "powershell.exe" and
process.command_line : ("*Invoke-WebRequest*" or "* iwr *" or "*DownloadFile*") and
process.command_line : ("*.exe*" or "*.dll*" or "*.dat*")
```

**Why it matters:** This identifies script-based transfer of executable content, including the ransomware staging observed in the lab.

**Tuning:** Allow approved software repositories only with additional checks for signer, destination path, parent process, user, and domain age.

## Phishing Email Triage Logic

The exact syntax depends on the secure email gateway, but the following combination is useful for correlation:

```text
external sender
AND sender domain != reply-to domain
AND (SPF fail OR DMARC fail)
AND attachment type IN (cab, rar, iso, img, exe, js, hta)
```

No single condition should automatically define a phishing verdict. Mailing lists, customer-support platforms, and third-party senders can create legitimate mismatches. The strongest alerts combine identity anomalies, authentication, attachment risk, reputation, and user interaction.

## Validation Checklist

- Confirm the query returns the intended event type and fields.
- Test against a representative historical time range.
- Document expected legitimate activity and exclusions.
- Add host, user, parent process, signer, and command-line context.
- Define severity from evidence and asset criticality.
- Record response steps and the data needed to close the alert.
- Revisit tuning when software, infrastructure, or business processes change.

## Related Case

See [Boogeyman3: Phishing to Ransomware Staging](../docs/03-Boogeyman3-Phishing-to-Ransomware-Investigation-Elastic-Security.md) for the evidence that led to these hunting ideas.
