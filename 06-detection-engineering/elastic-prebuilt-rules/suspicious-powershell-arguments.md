# Suspicious Windows PowerShell Arguments

## Source

Elastic prebuilt detection rule

Repository:
https://github.com/elastic/protections-artifacts/

## Rule Purpose

Identifies the execution of PowerShell with suspicious argument values. This behavior is often observed during malware
installation leveraging PowerShell.

## MITRE ATT&CK

[[threat]]
framework = "MITRE ATT&CK"
[[threat.technique]]
id = "T1059"
name = "Command and Scripting Interpreter"
reference = "https://attack.mitre.org/techniques/T1059/"
[[threat.technique.subtechnique]]
id = "T1059.001"
name = "PowerShell"
reference = "https://attack.mitre.org/techniques/T1059/001/"

[threat.tactic]
id = "TA0002"
name = "Execution"
reference = "https://attack.mitre.org/tactics/TA0002/"

## Detection Logic

The rule identifies PowerShell executions containing suspicious command-line arguments such as:

- encoded commands
- WebClient downloads
- DownloadString execution
- base64 encoded payloads
- reflection-based execution

Example indicators:

- -enc
- -encodedcommand
- DownloadString
- WebClient
- IEX

## Lab Validation

Atomic Red Team simulation:

T1059.001 — Test 17

Command executed:

Invoke-AtomicTest T1059.001 -TestNumbers 17

## Result

The Elastic rule **triggered successfully** after the encoded PowerShell execution.

## Telemetry Observed

process.name: powershell.exe

process.command_line contained encoded PowerShell arguments.

## Conclusion

The Elastic prebuilt rule successfully detected the simulated attacker behavior.
