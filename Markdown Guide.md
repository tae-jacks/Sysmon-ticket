#  Sysmon Detection Guide

##  Objective
Simulate and detect suspicious PowerShell-based activity using Sysmon, and document the detection logic for portfolio and recruiter visibility.

---

##  Lab Environment
- **OS:** Windows 11
- **Tools Used:**
  - Sysmon v14 with custom XML config
  - PowerShell for threat simulation
  - Windows Event Viewer for log analysis
- **User Accounts:** SYSTEM, family\cody
- **Network:** Local IP range (10.0.0.x)

---

##  Sysmon Events Captured

| Event ID | Description         |
|----------|---------------------|
| 1        | Process Creation    |
| 3        | Network Connection  |
| 5        | Process Termination |
| 7        | Image Loaded        |
| 11       | File Created        |

---

##  Simulation Steps

1. Executed `Light pink-punk-punkweed.exe` to spawn `cmd.exe`
2. Launched PowerShell with `-EncodedCommand` to simulate obfuscated execution
3. Triggered outbound HTTP traffic to `10.0.0.80:80`
4. Loaded DLLs via `FeedbackHub.exe`
5. Created `.pf` file via `svchost.exe` in the Windows Prefetch directory
6. Observed automatic process termination (Event ID 5)

---

##  Event Breakdown

###  Event ID 1 – Process Creation

Parent Process: Light pink-punk-punkweed.exe
Child Process: cmd.exe
Executable Path: C:\WINDOWS\system32\cmd.exe
User: SYSTEM
Timestamp: 2023-10-25T12:45:59.716Z

### Event ID 3 - Network Connection

Source Process: powershell.exe
Source IP: 10.0.0.80
Destination IP: 10.0.0.80
Destination Port: 80 (HTTP)
User: family\cody
Timestamp: 2015-10-15T18:29:42.670Z

### Event ID 7 - Image Loaded

Process: FeedbackHub.exe
Loaded DLLs:
  - ntdll.dll
  - kernel32.dll
  - KernelBase.dll
  - FeedbackHub.NativeCpp.WinRTWrapper.dll
Signature: Microsoft
User: NT AUTHORITY\SYSTEM
Timestamp: 2023-10-25T17:06:08.975Z

### Event ID 11 - File Created

Process: svchost.exe
Target File: C:\Windows\Prefetch\SNIPPINGTOOL.EXE-7CE845B8.pf
User: NT AUTHORITY\SYSTEM
Creation Time: 2023-10-25T18:33:11.048Z

### Event ID 5 - Process Terminated (Automatically Triggered)
Sysmon logs Event ID 5 when a monitored process ends. In this case, PowerShell.exe terminated after execution. This event is captured by default and does not require explicit configuration.


MITRE ATT&CK MAPPING

Technique - PowerShell, ID - T1059.001 Description - Execution via PowerShell

Technique - Command and Scripting Interpreter , ID - T1059 Description - General script execution

Technique - Application Layer Protocol, ID - T1071.001 Description - C2 over HTTP

Technique - DLL Side-Loading, ID - T1073 Description - DLLs loaded during execution

Technique - File Creation, ID - T1105 Description - Staging or payload delivery

Technique - Process Termination, ID - T1106 Description - Cleanup or evasion after execution


 Artifacts
- Sysmon Config XML
- Mock Ticket
- Screenshots Folder
- Event ID 1 – Process Creation
- Event ID 3 – Network Connection
- Event ID 7 – Image Loaded
- Event ID 11 – File Created
