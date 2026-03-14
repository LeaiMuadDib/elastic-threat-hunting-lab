## PowerShell Execution Policy Issue

While importing the Invoke-AtomicRedTeam module, PowerShell blocked execution due to the system execution policy.

Error:
"running scripts is disabled on this system"

Resolution used in lab:

Set-ExecutionPolicy Bypass -Scope Process

This temporarily allows scripts only for the current PowerShell session and does not permanently change system security settings.

Possible detection logic for later:
`process.name: powershell.exe AND process.command_line: *ExecutionPolicy Bypass*`
