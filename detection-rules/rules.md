## Rule 1 - Brute Force Login Detection
**EventCode** 4625 (Failed Logon)
**SPL Query**
index=* EventCode=4625 | stats count by Account_Name | sort -count
**Alert Settings:** Scheduled hourly - triggers when results > 0
**What it detects:** Account with repeated failed login attempts, consistent with a brute force or password spraying attack.
## Rule 2 - New User Account Created
**EventCode** 4720 (User Account Created)
**SPL Query**
index=* EventCode=4720 | table _time, Account_Name, src_user, host
**Alert Settings:** Scheduled hourly - triggers when results > 0
**What it detects:** Any new local user account creation - a common attacker persistence technique used to maintain access after initial compromise
## Rule 3 - PowerShell Execution Detection
**EventCode** 4688 (Process Creation)
**SPL Query**
index=* EventCode=4688 New_Process_Name="*powershell.exe" | table _time, Account_Name, New_Process_Name, Creator_Process_Name, host
**Alert Settings:** Scheduled hourly - triggers when results > 0
**What it detects:** Any PowerShell process spawned on the hsot - commonly abused by attackers for living off the land execution techniques
