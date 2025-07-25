```sql
// Translated content (automatically translated on 03-07-2025 02:07:59):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="C:\Windows\System32\OpenSSH\sshd.exe" or (tgt.process.image.path contains "\ssh.exe" and (tgt.process.cmdline contains "ProxyCommand=" or (tgt.process.cmdline contains "PermitLocalCommand" and tgt.process.cmdline contains "LocalCommand")))))
```


# Original Sigma Rule:
```yaml
title: Program Executed Using Proxy/Local Command Via SSH.EXE
id: 7d6d30b8-5b91-4b90-a891-46cccaf29598
status: test
description: Detect usage of the "ssh.exe" binary as a proxy to launch other programs.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Ssh/
    - https://github.com/LOLBAS-Project/LOLBAS/pull/211/files
    - https://gtfobins.github.io/gtfobins/ssh/
    - https://man.openbsd.org/ssh_config#ProxyCommand
    - https://man.openbsd.org/ssh_config#LocalCommand
author: frack113, Nasreddine Bencherchali
date: 2022-12-29
modified: 2023-01-25
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        # ParentCommandLine: '"C:\Windows\System32\OpenSSH\sshd.exe" -R'
        ParentImage: 'C:\Windows\System32\OpenSSH\sshd.exe'
    selection_cli_img:
        Image|endswith: '\ssh.exe'
    selection_cli_flags:
        - CommandLine|contains: 'ProxyCommand='
        - CommandLine|contains|all:
              - 'PermitLocalCommand'
              - 'LocalCommand'
    condition: selection_parent or all of selection_cli_*
falsepositives:
    - Legitimate usage for administration purposes
level: medium
```
