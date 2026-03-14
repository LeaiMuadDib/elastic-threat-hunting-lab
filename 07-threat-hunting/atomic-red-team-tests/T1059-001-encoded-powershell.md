## PowerShell Execution Policy Issue

While importing the Invoke-AtomicRedTeam module, PowerShell blocked execution due to the system execution policy.

Error:
"running scripts is disabled on this system"

Resolution used in lab:

Set-ExecutionPolicy Bypass -Scope Process

This temporarily allows scripts only for the current PowerShell session and does not permanently change system security settings.

Possible detection logic for later:
`process.name: powershell.exe AND process.command_line: *ExecutionPolicy Bypass*`

---

# Encoded PowerShell Investigation

## Summary

An Atomic Red Team simulation was executed to emulate encoded PowerShell execution.

The activity triggered the Elastic Security detection rule:

Suspicious Windows Powershell Arguments

## MITRE ATT&CK

T1059.001 — Command and Scripting Interpreter: PowerShell

## Attack Simulation

Atomic Red Team Test:

T1059.001 — Test 17

Command executed:

Invoke-AtomicTest T1059.001 -TestNumbers 17

## Telemetry Observed

Elastic captured the following process execution:

process.name: powershell.exe

process.parent.name: explorer.exe

process.command_line contained encoded PowerShell arguments.

## Detection

Rule triggered:

Suspicious Windows Powershell Arguments

Severity: Medium

Risk Score: 47

## Analysis

Encoded PowerShell execution is frequently used by adversaries to evade signature detection and execute malicious payloads.

The Elastic prebuilt rule successfully identified the suspicious command-line parameters.

## Conclusion

The Elastic Security environment successfully detected the simulated attack.

This validates:

• Endpoint telemetry ingestion  
• Detection rule functionality  
• Alerting pipeline
