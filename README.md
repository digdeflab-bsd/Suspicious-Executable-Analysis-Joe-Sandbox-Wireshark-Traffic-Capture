# Suspicious-Executable-Analysis-Joe-Sandbox-Wireshark-Traffic-Capture
#### Threat Intelligence / Malware Analysis

![Joe Sandbox](https://img.shields.io/badge/Joe%20Sandbox-0052CC?style=for-the-badge)

📜*This report was produced for educational and portfolio purposes in a controlled virtual lab environment. Based solely on data provided by the analyst (Joe Sandbox PDF report and analyst virtual lab). All inferences are labeled as such. No external threat intelligence databases were queried. This report does not constitute a definitive legal or forensic finding. It must be reviewed and validated in the context of the specific environment where this software was or may be deployed.*

<div>
    <img src="https://img.shields.io/badge/-YouTube-FF0000?&style=for-the-badge&logo=YouTube&logoColor=white" />
</div>

| Scanner | Analyst Virtual Lab YT Video |
| --- | ---|
| Joe Sandbox | https://youtu.be/yaFaAENrqnM |

# ISOMate.exe - Security Investigation Report

**Analyst:** Virtual Lab Investigation  
**Platform:** Joe Sandbox Cloud Basic v44.0.0 (Smoke Quartz) + Wireshark Traffic Capture  
**Report Type:** Threat Intelligence / Malware Analysis  
**Classification:** TLP:WHITE (suitable for public sharing)

---

## Table of Contents

1. Executive Summary
2. Technical Summary
3. Investigation Methodology
4. Findings and Analysis
5. MITRE ATT&CK Mapping
6. Network Behavior Analysis
7. VirusTotal vs Joe Sandbox Comparison
8. Risk and Impact Assessment
9. Recommendations
10. Limitations and Unknowns
11. References

---

## 1. Executive Summary

A 99-page Joe Sandbox Cloud report was generated for a file named **ISOMate.exe** (MD5: B3F65CBA5C826F067270866A47D64082), submitted, as part of a virtual lab investigation.

**Key findings in plain language:**

- ISOMate.exe is a digitally signed Windows installer for a commercial tool called ISOMate Pro, published by SYSGeeker Technology Limited (a Chinese entity registered in Shenzhen). It installs software to help users download and manage Windows ISO images.
- The sandbox rated the file with a score of 14 out of 100, with a confidence of only 40%, and ultimately classified it as CLEAN in the detection field, though behavior indicators elevated it to SUSPICIOUS or MALICIOUS in specific behavioral categories.
- The most significant finding is that once installed, ISOMate Pro launches a non-interactive PowerShell process that queries all attached USB disks, enumerates their partitions and drive letters, and outputs that information. This behavior, combined with the loading of the BitLocker PowerShell module, is unusual for a simple ISO downloader and warrants scrutiny.
- The software makes outbound HTTPS connections to a domain (www.syscute.com) hosted on a Vultr cloud VPS in the United States. It also references a registration check endpoint at www.regserver3.com, consistent with license validation telemetry.
- No malware configuration, YARA signature matches, or Suricata IDS alerts were triggered. No injected processes were observed. The 87 files dropped are all consistent with a Qt6-based application installer.
- The overall assessment is that this is likely a legitimate but privacy-invasive commercial application that collects storage device information and sends telemetry home. It is not conclusively malicious, but its behavior requires policy-level decisions in enterprise environments.

**Business risk:** Low to moderate. Not a clear threat actor tool, but installs software from a low-reputation publisher that probes attached storage devices.

---

## 2. Technical Summary

| Field | Value |
|---|---|
| Sample Name | ISOMate.exe |
| Analysis ID | 1929752 |
| MD5 | B3F65CBA5C826F067270866A47D64082 |
| SHA1 | 676FAFA9964CFCBA29B7BFBBE07161468742DEA7 |
| SHA256 | FEDEA108C4C0AF0566D926878B12607AB8405EBE3BE1C283EEE761CDA002CD4E |
| File Size | 23,924,360 bytes (~23.9 MB) |
| File Type | PE32 executable (GUI), Intel 80386, Inno Setup installer |
| Entropy | 7.99 (high - consistent with compression/packing) |
| Compiler | Borland Delphi (Inno Setup wrapper) |
| Digital Signature | Valid - CN=SYSGeeker Technology Limited (SSL.com EV Code Signing, expires Oct 2027) |
| Sandbox Score | 14/100, Confidence 40% |
| Final Detection | CLEAN (Joe Sandbox classification field) |
| Contacted IP | 45.32.86.219 (www.syscute.com, AS-VULTR, United States) |
| Analysis Duration | 7 minutes 2 seconds |
| Analysis Environment | Windows 10 x64 22H2 |

**Process chain observed:**

```
ISOMate.exe (PID 6996)
  └── ISOMate.tmp (PID 7084) [Inno Setup unpacker]
        └── ISOMate Pro.exe (PID 4856) [Qt6 application]
              └── powershell.exe (PID 2336) [USB enumeration command]
                    └── conhost.exe (PID 352)
```

**PowerShell command executed (verbatim from report):**

```powershell
powershell -NoProfile -Command "Get-Disk | Where-Object { $_.BusType -eq 'USB' } |
ForEach-Object { $disk = $_; $partitions = Get-Partition -DiskNumber $disk.Number
-ErrorAction SilentlyContinue; $letter = ''; if ($partitions) { foreach ($p in
$partitions) { $vol = Get-Volume -Partition $p -ErrorAction SilentlyContinue;
if ($vol -and $vol.DriveLetter) { $letter = $vol.DriveLetter + ':'; break } } }
Write-Output ('{0}|{1}|{2}|{3}' -f $disk.Number, $disk.FriendlyName, $disk.Size, $letter) }"
```

This command enumerates all USB-attached disks, their friendly names, sizes, and assigned drive letters, and outputs them in a structured pipe-delimited format. This is consistent with the application's ISO management purpose (detecting where to write ISOs), but it also represents a non-obvious collection of hardware inventory data.

**Sigma signature triggered:**

```
Sigma detected: Non Interactive PowerShell Process Spawned
```

**Joe Sandbox signature triggered:**

```
Loading BitLocker PowerShell Module
```

---

## 3. Investigation Methodology

### 3.1 Data Sources Used

- Joe Sandbox Cloud Basic v44.0.0 full 99-page report 
- Wireshark network traffic capture
- Static PE analysis data embedded in the sandbox report
- DNS query and TCP packet-level data from the sandbox network capture

### 3.2 Analysis Approach

The investigation followed a structured three-perspective methodology:

**Blue Team (Defender):** Reviewed all process activity, file drops, registry modifications, network connections, and PowerShell behavior for indicators of compromise or policy violations.

**Red Team (Attacker):** Evaluated what an attacker could do with the observed capabilities: USB enumeration, BitLocker module loading, outbound HTTPS to a VPS, and non-interactive PowerShell spawned from a GUI application.

**Grey Hat:** Assessed whether observed behaviors, individually plausible for a legitimate tool, form a meaningful pattern when viewed collectively.

### 3.3 Tools Used

- Joe Sandbox Cloud (dynamic analysis sandbox)
- Wireshark (network traffic capture)
- ReversingLabs (static AV scan, 0% detection)
- VirusTotal (2% detection on initial sample)
- Avira URL Cloud (URL reputation scanning, all URLs rated safe)

---

## 4. Findings and Analysis

### Finding 1: Legitimate-Looking Signed Installer with Anomalous PowerShell Behavior

**What it is:** ISOMate.exe is a valid Inno Setup installer, signed with an Extended Validation (EV) code signing certificate issued by SSL.com to SYSGeeker Technology Limited (a Chinese entity registered in Shenzhen, Guangdong, PRC). The signature validates successfully. The installer deploys a Qt6-based Windows application with a full set of dependencies including aria2c.exe (a legitimate open-source download manager), multiple Qt6 DLLs, SQL drivers, and image format plugins.

**Why it matters:** EV code signing certificates require physical verification of the business entity and are harder to obtain fraudulently than standard certificates. This suggests the software is from a real, registered company, not a drive-by threat actor. However, EV certificates have been abused in the past by software vendors distributing aggressive adware or data-harvesting tools that remain technically legal.

**Evidence:** Authenticode signature valid (SSL.com EV RSA R3 CA), subject CN=SYSGeeker Technology Limited, SERIALNUMBER=91440300MA5F16HJ5W, valid until 29/10/2027.

**What is uncertain:** SYSGeeker Technology Limited's reputation and privacy practices are not directly assessed in the report. The serial number format (91440300MA5F16HJ5W) is consistent with a Chinese unified social credit code, confirming business registration, but no further due diligence data is available from the sandbox report alone.

---

### Finding 2: Non-Interactive PowerShell Spawned from GUI Application

**What it is:** ISOMate Pro.exe (PID 4856) spawns a non-interactive PowerShell process (PID 2336) using `-NoProfile` to enumerate USB storage devices, including disk numbers, friendly names, total sizes, and drive letters. The output is formatted as a pipe-delimited string.

**Why it matters:** Spawning a hidden, non-interactive PowerShell process from a GUI desktop application is a known MITRE ATT&CK technique (T1059.001 - Command and Scripting Interpreter: PowerShell). While this behavior is plausible for an application that needs to detect available USB drives for ISO writing, the specific data collected (disk size, friendly name, drive letter) goes beyond what is strictly needed to detect that a USB drive is present.

**Red team perspective:** If this application were repurposed or trojanized, the pipe-delimited output format is trivially parseable and could be exfiltrated. The `-NoProfile` flag suppresses user-defined PowerShell profiles, which can also suppress some defensive logging configurations.

**Blue team perspective:** Monitor for powershell.exe spawned with `-NoProfile -Command` as a child of GUI application processes in EDR telemetry. This specific pattern matches the Sigma rule "Non Interactive PowerShell Process Spawned" that fired in the sandbox.

**Evidence:** Process tree (PID 2336, parent PID 4856), full command line recorded in report page 1 and page 80.

---

### Finding 3: BitLocker PowerShell Module Loaded

**What it is:** During the PowerShell execution chain, the BitLocker PowerShell module was loaded. This is confirmed by both the Joe Sandbox signature ("Loading BitLocker PowerShell Module") and the process file read activity showing the BitLocker.psd1 and BitLocker.psm1 files being accessed (pages 87-88 of the report).

**Why it matters:** The BitLocker module gives access to cmdlets such as Get-BitLockerVolume, Enable-BitLocker, Suspend-BitLocker, and Remove-BitLockerKeyProtector. For an application that only needs to enumerate USB drives, there is no obvious reason to load the BitLocker module. This is the most anomalous single behavioral finding in the report.

**Hypothesis 1 (Benign):** PowerShell's automatic module discovery loads BitLocker as a side effect of loading the Storage module (which is needed for Get-Disk and Get-Volume). When the Storage module initializes, it may trigger enumeration of all available storage-related modules including BitLocker. [Inference - not confirmed by report data alone]

**Hypothesis 2 (Concerning):** The application intentionally loads the BitLocker module to check whether attached volumes are BitLocker-protected, potentially to identify encrypted drives and report that information back via its telemetry channel.

**Evidence:** Joe Sandbox signature "Loading BitLocker PowerShell Module" (page 6), file read activity for BitLocker.psd1 and BitLocker.psm1 (pages 87-88), MITRE ATT&CK mapping includes "OS Credential Dumping" and "LSA Secrets" in the Credential Access column (page 6-7).

**Important caveat:** The MITRE ATT&CK matrix in the Joe Sandbox report maps observed behaviors to techniques but does not confirm that all listed techniques were actually exploited. The presence of these mappings reflects the sandbox's automated classification of observed API calls, not confirmed malicious credential access.

---

### Finding 4: Outbound HTTPS to Vultr VPS (www.syscute.com / 45.32.86.219)

**What it is:** The installed application (ISOMate Pro.exe, PID 4856) makes an outbound TLS connection on port 443 to 45.32.86.219, which resolves to www.syscute.com. This domain hosts the vendor's website (syscute.com). DNS resolution was confirmed via a standard A record query to 1.1.1.1 (Cloudflare DNS). Network traffic was observed at 08:34:44-08:34:46 CEST (16 TCP packets captured).

**URLs contacted on www.syscute.com:**
- /api/isomate-versions.json (version check)
- /guide/isomate7.html (user guide)
- /support.html (support page)
- /buy/isomate7.html (purchase page)
- /yl and /Ah and /Qv# (short URLs - purpose unclear)

**Registration check observed:**
- https://www.regserver3.com/admin/checkregister.php (with POST data `application/x-www-form-urlencoded ISOMate7/4.7.536p0`) - this is a license validation endpoint.

**Why it matters:** The connection to syscute.com is expected vendor telemetry. The connection to regserver3.com is a license check. Both resolve to unknown-reputation infrastructure. The short path endpoints (/yl, /Ah, /Qv#) are unusual and their purpose cannot be determined from the sandbox data alone.

**Evidence:** DNS query table (page 51), TCP packet log (page 50), URL detection table (pages 4-5), behavior graph (page 2).

---

### Finding 5: Dropped Files - Full Qt6 Application Suite

**What it is:** The installer drops 87+ files, none of which are flagged as malicious by ReversingLabs. Files include the full Qt6 runtime (Qt6Core.dll, Qt6Gui.dll, Qt6Network.dll, Qt6Widgets.dll, Qt6Svg.dll, Qt6Sql.dll), Microsoft Visual C++ redistributables (msvcp140.dll, vcruntime140.dll), D3D compiler, OpenGL software renderer, aria2c.exe (download manager), and a complete set of SQL drivers, image format plugins, TLS backends, and platform plugins.

**Why it matters:** The dropped file set is entirely consistent with a legitimate Qt6-based Windows application. The inclusion of aria2c.exe is notable - aria2c is an open-source multi-protocol download manager that supports HTTP, HTTPS, FTP, and BitTorrent. It is the likely mechanism used to download Windows ISO files. aria2c itself is clean (0% ReversingLabs detection).

**Evidence:** Dropped files table (pages 3-4, 16-44), all ReversingLabs detections at 0%.

---

### Finding 6: Registry Modifications - Standard Uninstall Registration

**What it is:** The installer writes standard Windows uninstall registry entries under HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{1E3C2ED9-8462-41A9-822C-5470DBDC3CCC}_is1. Values written include publisher (SYSCute), version (4.7.5), install path, uninstall string, and URL fields pointing to syscute.com.

**Why it matters:** This is entirely standard installer behavior. It does not represent a threat but confirms the software installs system-wide (requires elevation) and registers itself in a way consistent with commercial software.

**Evidence:** Registry key value creation table (pages 77-79).

---

### Finding 7: API Interceptor - Sleep Calls Modified

**What it is:** The Joe Sandbox API interceptor modified 3,030 Sleep() calls in ISOMate Pro.exe and 38 Sleep() calls in powershell.exe to accelerate analysis.

**Why it matters:** A very high number of Sleep() calls (3,030) in the main application process is notable. Malware often uses Sleep() calls to delay execution past sandbox timeout windows. However, Qt6 GUI applications also legitimately use Sleep() calls extensively for animation timers, network request polling, and UI event loops. [Inference] The count alone is not conclusive evidence of anti-sandbox behavior, but it is worth noting.

**Evidence:** Simulations / Behavior and APIs table (page 5).

---

## 5. MITRE ATT&CK Mapping

The following techniques were mapped by Joe Sandbox based on observed behavior. Note that presence in the ATT&CK matrix does not confirm malicious intent for each technique.

| Tactic | Technique | Observed Evidence | Confidence |
|---|---|---|---|
| Execution | T1059.001 - PowerShell | Non-interactive powershell.exe spawned from GUI app | High (confirmed) |
| Persistence | T1547.001 - Registry Run Keys / Startup Folder | Registry writes observed | Medium (standard installer) |
| Defense Evasion | T1055 - Process Injection | Mapped by sandbox (no confirmed injection observed) | Low (automated mapping) |
| Defense Evasion | T1497 - Virtualization/Sandbox Evasion | 3,030 Sleep calls intercepted | Low (may be legitimate) |
| Defense Evasion | T1036 - Masquerading | DLL Side-Loading noted in ATT&CK matrix | Low (automated mapping) |
| Discovery | T1120 - Peripheral Device Discovery | USB disk enumeration via Get-Disk | High (confirmed) |
| Discovery | T1082 - System Information Discovery | System information queries observed | Medium (confirmed) |
| Collection | T1025 - Data from Removable Media | USB device info collected | Medium (confirmed, purpose unclear) |
| Command and Control | T1573 - Encrypted Channel | TLS/HTTPS to 45.32.86.219 | High (confirmed) |
| Command and Control | T1071 - Application Layer Protocol | HTTPS traffic to syscute.com | High (confirmed) |

---

## 6. Network Behavior Analysis

### DNS and TCP Summary

- One DNS A query issued: www.syscute.com resolved to 45.32.86.219 via 1.1.1.1
- 16 TCP packets observed between 192.168.2.4 and 45.32.86.219 on port 443
- All traffic encrypted via TLS (HTTPS); payload content not readable in sandbox capture
- No DNS-over-HTTPS (DoH) used
- No connections to known malicious infrastructure
- No outbound traffic to unexpected ports (no raw TCP C2, no IRC, no non-standard ports observed)

### ASN Context

45.32.86.219 is hosted on AS20473 (AS-VULTR, The Constant Company LLC, United States). Vultr is a legitimate cloud VPS provider widely used by businesses but also commonly used by threat actors due to easy, anonymous provisioning. The use of Vultr hosting for a vendor's primary application server is not unusual but does reduce infrastructure trust compared to hosting on major CDNs.

### Wireshark Capture (Lab Video Observations)

Based on the video uploaded from the virtual lab:

- TLS handshake observed toward 45.32.86.219:443 confirming the outbound connection
- Traffic volume and timing are consistent with an API version check and ISO metadata fetch
- No obvious beaconing pattern at regular intervals was visible during the capture window
- [Limitation] The video capture window was limited; long-term beaconing behavior could not be assessed

---

## 8. Risk and Impact Assessment

### Likelihood

The likelihood that ISOMate.exe is a targeted malware payload deployed by a threat actor is LOW based on available evidence. The software has a valid EV certificate, a plausible commercial purpose, a consistent file set, and no known malware configuration.

The likelihood that ISOMate.exe collects and transmits hardware inventory information (USB device details, potentially BitLocker status) to vendor infrastructure is MEDIUM TO HIGH based on observed behavior.

### Potential Impact

| Scenario | Likelihood | Impact |
|---|---|---|
| Trojanized supply chain attack via ISOMate installer | Low | Critical |
| Privacy-invasive telemetry (USB device profiling) | Medium | Low to Medium |
| License check exfiltrating host identifiers | Medium | Low |
| False positive - fully legitimate application | High | None |

### Affected Systems

Any Windows system where a user installs ISOMate.exe with administrative privileges. The installer writes to Program Files (x86) and HKLM registry, requiring elevation.

---

## 9. Recommendations

### Immediate Actions

**For individuals:** Review the privacy policy of SYSGeeker Technology Limited before use. Consider whether a commercial ISO downloader that probes your USB devices and sends telemetry to a Vultr VPS is appropriate for your threat model. Free, open-source alternatives (e.g., Rufus, balenaEtcher, the Microsoft Media Creation Tool) do not exhibit this behavior pattern.

**For organizations (Blue Team):**

1. Add a detection rule for powershell.exe spawned with `-NoProfile -Command` as a child of any non-system GUI application process. Alert on this in your EDR or SIEM.
2. Block or alert on outbound connections to regserver3.com at the network perimeter. This domain serves no legitimate purpose outside of ISOMate license validation.
3. If ISOMate Pro is not an approved application in your environment, block the hash (SHA256: FEDEA108C4C0AF0566D926878B12607AB8405EBE3BE1C283EEE761CDA002CD4E) in your endpoint protection platform.
4. If application control (AppLocker or WDAC) is deployed, verify that ISOMate Pro is not on the allowlist.

### Detection Opportunities

```
# Sigma-style detection concept (not a fully validated rule)
# Detect non-interactive PowerShell spawned from a GUI application process
# performing USB disk enumeration

Process: powershell.exe
CommandLine|contains|all:
  - '-NoProfile'
  - 'Get-Disk'
  - 'BusType'
  - 'USB'
ParentImage|endswith: '.exe'
ParentImage|not|contains:
  - 'powershell'
  - 'cmd'
  - 'wscript'
  - 'cscript'
```

### Longer-Term Recommendations

1. Implement a software allowlisting policy that requires approval for any application that spawns PowerShell with `-NoProfile` from a GUI context.
2. Establish a vendor assessment process for commercial software installed by end users. EV code signing alone is not sufficient evidence of acceptable behavior.
3. Consider deploying network visibility tools (e.g., Zeek, Suricata) on endpoint egress to identify TLS connections to VPS infrastructure from non-browser processes.

---

## 10. Limitations and Unknowns

| Item | Status |
|---|---|
| TLS payload content of HTTPS connections | Unknown - encrypted, not decryptable without MITM proxy |
| What data, if any, is sent to syscute.com beyond version checks | Unknown |
| What the short-path endpoints (/yl, /Ah, /Qv#) do | Unknown |
| Whether BitLocker module loading is intentional or a side effect of Storage module auto-discovery | Unknown - requires source code or deeper instrumentation |
| Behavior after the 7-minute sandbox timeout | Not captured |
| NtCreateKey, NtOpenKeyEx, NtProtectVirtualMemory, NtQueryValueKey, NtSetInformationFile call details | Truncated by report size limits |
| Wireshark capture payload analysis | Limited to video - no PCAP file was analyzed |
| SYSGeeker Technology Limited privacy practices and data retention | Not assessed |
| Whether regserver3.com infrastructure is shared with other vendors or exclusively used by SYSGeeker | Unknown |

---

## 11. References

- Joe Sandbox documentation: joes-security.com (do not access from a production environment)
- MITRE ATT&CK Framework: attack.mitre.org
- Sigma detection rules: github.com/SigmaHQ/sigma
- CIS Benchmarks for Windows (for endpoint hardening context): cisecurity.org
- Microsoft documentation on PowerShell execution policies: docs.microsoft.com/powershell
- Vultr ASN (AS20473) information: available via public BGP routing databases
- SSL.com EV Code Signing CA information: ssl.com/certificates/code-signing
- aria2c open source download manager: aria2.github.io (verified legitimate open source project)

---

*Document version: 1.0 | Classification: TLP:WHITE*
