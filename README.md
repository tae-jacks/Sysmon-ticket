# Sysmon-ticket

### 🐛 Ticket Title:
Suspicious PowerShell Execution with Network Activity, DLL Load, File Creation, and Process Termination

---

### 📅 Date Reported:
2025-10-27

### 🧑‍💻 Analyst:
Octavius (SOC Tier 1)

---

### 🧠 Summary:
Sysmon detected a suspicious PowerShell process initiated by a custom executable, followed by outbound network activity, DLL loading, file creation, and process termination. This behavior may indicate obfuscated script execution, staging, or early-stage compromise.

---

### 📌 Detection Details:

#### 🔹 Event ID 1 – Process Creation
- **Parent Process:** `Light pink-punk-punkweed.exe`
- **Child Process:** `cmd.exe`
- **Executable Path:** `C:\WINDOWS\system32\cmd.exe`
- **Parent Image:** `C:\Program Files (x86)\Light pink-punk-punkweed.exe`
- **User:** `SYSTEM`
- **Timestamp:** 2023-10-25T12:45:59.716Z

#### 🔹 Event ID 3 – Network Connection
- **Source Process:** `powershell.exe`
- **Source IP:** `10.0.0.80`
- **Source Port:** `51485`
- **Destination IP:** `10.0.0.80`
- **Destination Port:** `80`
- **Protocol:** TCP
- **Initiated:** True
- **User:** `family\cody`
- **Timestamp:** 2015-10-15T18:29:42.670Z

#### 🔹 Event ID 7 – Image Loaded
- **Process:** `FeedbackHub.exe`
- **Loaded DLLs:**
  - `ntdll.dll`
  - `kernel32.dll`
  - `KernelBase.dll`
  - `FeedbackHub.NativeCpp.WinRTWrapper.dll`
- **Signature:** Microsoft
- **User:** `NT AUTHORITY\SYSTEM`
- **Timestamp:** 2023-10-25T17:06:08.975Z

#### 🔹 Event ID 11 – File Created
- **Process:** `svchost.exe`
- **Target File:** `C:\Windows\Prefetch\SNIPPINGTOOL.EXE-7CE845B8.pf`
- **Creation Time:** 2023-10-25T18:33:11.048Z
- **User:** `NT AUTHORITY\SYSTEM`

#### 🔹 Event ID 5 – Process Terminated *(Automatically Triggered)*
- Sysmon logs Event ID 5 when a monitored process ends. In this case, `powershell.exe` terminated after execution. This event is captured by default and does not require explicit configuration.

---

### 🧭 MITRE ATT&CK Mapping:

| Technique | ID          | Description                        |
|-----------|-------------|------------------------------------|
| PowerShell | T1059.001   | Execution via PowerShell           |
| Command and Scripting Interpreter | T1059 | General script execution         |
| Application Layer Protocol | T1071.001 | C2 over HTTP                      |
| DLL Side-Loading | T1073 | DLLs loaded during execution       |
| File Creation | T1105 | Staging or payload delivery         |
| Process Termination | T1106 | Cleanup or evasion after execution|

---

### 🔍 Investigation Notes:
- PowerShell was launched indirectly via a custom executable (`punkweed.exe`), suggesting obfuscation or evasion.
- Network activity was local and used HTTP over port 80.
- DLLs loaded by FeedbackHub.exe are signed and expected, but useful for visibility.
- File creation (`.pf` file) is typical of application execution, but confirms write activity.
- Process termination was expected and logged automatically.

---

### ✅ Remediation:
- No malicious payload detected.
- Sysmon config updated to alert on indirect PowerShell launches, outbound traffic, DLL loads, and file creation.
- Detection logic documented and mapped to MITRE for portfolio use.

---

### 📁 Artifact Links:
- [Sysmon Config XML](link-to-your-config.xml)
- [Annotated Screenshot – Event ID 1](![alt text](<Event 1.png>))
- [Annotated Screenshot – Event ID 3](![alt text](<Event 3.png>))
- [Annotated Screenshot – Event ID 7](![alt text](<Event 7.png>))
- [Annotated Screenshot – Event ID 11](![alt text](<Event 11.png>))

---

### 🗒️ Notes:
This ticket was created as part of a portfolio project to demonstrate detection logic, MITRE mapping, and documentation skills using Sysmon. Event ID 5 was automatically triggered upon process termination and included for completeness.
