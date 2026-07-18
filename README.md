# ProcessExplorer
A small Windows process inspection tool built for demonstrating Windows Internals. It queries a process by PID and dumps its security context, token user, integrity level, enabled privileges, session, parent, and PPL protection status.
 
## Usage
 
```
procexp.exe <PID>
```
 
```
C:\> procexp.exe 9512
[*] PID          : 9512
[*] Parent PID   : 3120
[*] Session ID   : 1
[*] PPL Protected: No
[*] User         : WRK01\Josh Gates
[*] Integrity    : Medium
[*] Enabled Privileges:
    [+] SeChangeNotifyPrivilege
```
 
## What it shows
 
| Field | What it means |
|---|---|
| PID / Parent PID | Process ID and the PID of whoever spawned it |
| Session ID | 0 = system/services session, 1+ = interactive user session |
| PPL Protected | Whether the process has Protected Process Light enabled and at what signer level |
| User | The account the process is running as, resolved from the token SID |
| Integrity | MIC integrity level -- Untrusted / Low / Medium / High / System |
| Enabled Privileges | OS-level privileges currently active on the token |
 

 
## Requirements
 
- Windows 10+
- No admin required for most processes
- Admin needed to inspect elevated or system processes
- Some system processes (PPL-protected) will deny `OpenProcess` entirely even as admin

## What to try
 
Run a program normally, then run it as administrator. Query both PIDs and compare the output. The integrity level jumps from Medium to High and the privilege list grows significantly. That difference is UAC in action.
 
To inspect a system process like `lsass.exe` you'll need to run procexp itself as administrator.
 
