```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\userinit.exe" and (not tgt.process.image.path contains ":\WINDOWS\explorer.exe") and (not ((tgt.process.cmdline contains "netlogon.bat" or tgt.process.cmdline contains "UsrLogon.cmd") or tgt.process.cmdline="PowerShell.exe" or (tgt.process.image.path contains ":\Windows\System32\proquota.exe" or tgt.process.image.path contains ":\Windows\SysWOW64\proquota.exe") or (tgt.process.image.path contains ":\Program Files (x86)\Citrix\HDX\bin\cmstart.exe" or tgt.process.image.path contains ":\Program Files (x86)\Citrix\HDX\bin\icast.exe" or tgt.process.image.path contains ":\Program Files (x86)\Citrix\System32\icast.exe" or tgt.process.image.path contains ":\Program Files\Citrix\HDX\bin\cmstart.exe" or tgt.process.image.path contains ":\Program Files\Citrix\HDX\bin\icast.exe" or tgt.process.image.path contains ":\Program Files\Citrix\System32\icast.exe") or not (tgt.process.image.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Uncommon Userinit Child Process
id: 0a98a10c-685d-4ab0-bddc-b6bdd1d48458
related:
    - id: 21d856f9-9281-4ded-9377-51a1a6e2a432
      type: similar
status: test
description: Detects uncommon "userinit.exe" child processes, which could be a sign of uncommon shells or login scripts used for persistence.
references:
    - https://cocomelonc.github.io/persistence/2022/12/09/malware-pers-20.html
    - https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-sconfig#powershell-is-the-default-shell-on-server-core
author: Tom Ueltschi (@c_APT_ure), Tim Shelton
date: 2019-01-12
modified: 2023-11-14
tags:
    - attack.t1037.001
    - attack.persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\userinit.exe'
    filter_main_explorer:
        Image|endswith: ':\WINDOWS\explorer.exe'
    filter_optional_logonscripts:
        CommandLine|contains:
            - 'netlogon.bat'
            - 'UsrLogon.cmd'
    filter_optional_windows_core:
        # Note: This filter is mandatory on Windows Core machines as the default shell spawned by "userinit" is "powershell.exe".
        # https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-sconfig#powershell-is-the-default-shell-on-server-core
        CommandLine: 'PowerShell.exe'
    filter_optional_proquota:
        Image|endswith:
            - ':\Windows\System32\proquota.exe'
            - ':\Windows\SysWOW64\proquota.exe'
    filter_optional_citrix:
        Image|endswith:
            # As reported by https://github.com/SigmaHQ/sigma/issues/4569
            - ':\Program Files (x86)\Citrix\HDX\bin\cmstart.exe' # https://support.citrix.com/article/CTX983798/purpose-of-cmstart-command
            - ':\Program Files (x86)\Citrix\HDX\bin\icast.exe' # https://support.citrix.com/article/CTX983798/purpose-of-cmstart-command
            - ':\Program Files (x86)\Citrix\System32\icast.exe'
            - ':\Program Files\Citrix\HDX\bin\cmstart.exe' # https://support.citrix.com/article/CTX983798/purpose-of-cmstart-command
            - ':\Program Files\Citrix\HDX\bin\icast.exe' # https://support.citrix.com/article/CTX983798/purpose-of-cmstart-command
            - ':\Program Files\Citrix\System32\icast.exe'
    filter_optional_image_null:
        Image: null
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate logon scripts or custom shells may trigger false positives. Apply additional filters accordingly.
level: high
```
