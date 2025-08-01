```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " -n " or tgt.process.cmdline contains " /n " or tgt.process.cmdline contains " –n " or tgt.process.cmdline contains " —n " or tgt.process.cmdline contains " ―n ") and tgt.process.cmdline contains "Nul" and (tgt.process.cmdline contains " -f " or tgt.process.cmdline contains " /f " or tgt.process.cmdline contains " –f " or tgt.process.cmdline contains " —f " or tgt.process.cmdline contains " ―f " or tgt.process.cmdline contains " -q " or tgt.process.cmdline contains " /q " or tgt.process.cmdline contains " –q " or tgt.process.cmdline contains " —q " or tgt.process.cmdline contains " ―q ") and (tgt.process.cmdline contains "ping" and tgt.process.cmdline contains "del ")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Ping/Del Command Combination
id: 54786ddc-5b8a-11ed-9b6a-0242ac120002
status: test
description: Detects a method often used by ransomware. Which combines the "ping" to wait a couple of seconds and then "del" to delete the file in question. Its used to hide the file responsible for the initial infection for example
references:
    - https://blog.sygnia.co/kaseya-ransomware-supply-chain-attack
    - https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf
    - https://www.acronis.com/en-us/blog/posts/lockbit-ransomware/
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/blackbyte-exbyte-ransomware
author: Ilya Krestinichev
date: 2022-11-03
modified: 2024-03-05
tags:
    - attack.defense-evasion
    - attack.t1070.004
logsource:
    category: process_creation
    product: windows
detection:
    # Note: In the case of sysmon and similar logging utilities, see this discussion https://github.com/SigmaHQ/sigma/discussions/4277
    # Example: "C:\Windows\System32\cmd.exe"  /C ping 127.0.0.7 -n 3 > Nul & fsutil file setZeroData offset=0 length=524288 "C:\Users\User\Desktop\lockbit\lockbit.exe" & Del /f /q "C:\Users\User\Desktop\lockbit\lockbit.exe".
    selection_count:
        CommandLine|contains|windash: ' -n '
    selection_nul:
        CommandLine|contains: 'Nul' # Covers "> Nul" and ">Nul "
    selection_del_param:
        CommandLine|contains|windash:
            - ' -f '
            - ' -q '
    selection_all:
        CommandLine|contains|all:
            - 'ping' # Covers "ping" and "ping.exe"
            - 'del '
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
