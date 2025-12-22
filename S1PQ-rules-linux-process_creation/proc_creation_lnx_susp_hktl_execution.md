```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/crackmapexec" or tgt.process.image.path contains "/havoc" or tgt.process.image.path contains "/merlin-agent" or tgt.process.image.path contains "/merlinServer-Linux-x64" or tgt.process.image.path contains "/msfconsole" or tgt.process.image.path contains "/msfvenom" or tgt.process.image.path contains "/ps-empire server" or tgt.process.image.path contains "/ps-empire" or tgt.process.image.path contains "/sliver-client" or tgt.process.image.path contains "/sliver-server" or tgt.process.image.path contains "/Villain.py") or (tgt.process.image.path contains "/cobaltstrike" or tgt.process.image.path contains "/teamserver") or (tgt.process.image.path contains "/autorecon" or tgt.process.image.path contains "/httpx" or tgt.process.image.path contains "/legion" or tgt.process.image.path contains "/naabu" or tgt.process.image.path contains "/netdiscover" or tgt.process.image.path contains "/nuclei" or tgt.process.image.path contains "/recon-ng") or tgt.process.image.path contains "/sniper" or (tgt.process.image.path contains "/dirb" or tgt.process.image.path contains "/dirbuster" or tgt.process.image.path contains "/eyewitness" or tgt.process.image.path contains "/feroxbuster" or tgt.process.image.path contains "/ffuf" or tgt.process.image.path contains "/gobuster" or tgt.process.image.path contains "/wfuzz" or tgt.process.image.path contains "/whatweb") or (tgt.process.image.path contains "/joomscan" or tgt.process.image.path contains "/nikto" or tgt.process.image.path contains "/wpscan") or (tgt.process.image.path contains "/aircrack-ng" or tgt.process.image.path contains "/bloodhound-python" or tgt.process.image.path contains "/bpfdos" or tgt.process.image.path contains "/ebpfki" or tgt.process.image.path contains "/evil-winrm" or tgt.process.image.path contains "/hashcat" or tgt.process.image.path contains "/hoaxshell.py" or tgt.process.image.path contains "/hydra" or tgt.process.image.path contains "/john" or tgt.process.image.path contains "/ncrack" or tgt.process.image.path contains "/nxc-ubuntu-latest" or tgt.process.image.path contains "/pidhide" or tgt.process.image.path contains "/pspy32" or tgt.process.image.path contains "/pspy32s" or tgt.process.image.path contains "/pspy64" or tgt.process.image.path contains "/pspy64s" or tgt.process.image.path contains "/setoolkit" or tgt.process.image.path contains "/sqlmap" or tgt.process.image.path contains "/writeblocker") or tgt.process.image.path contains "/linpeas"))
```


# Original Sigma Rule:
```yaml
title: Linux HackTool Execution
id: a015e032-146d-4717-8944-7a1884122111
status: test
description: Detects known hacktool execution based on image name.
references:
    - https://github.com/Gui774ume/ebpfkit
    - https://github.com/pathtofile/bad-bpf
    - https://github.com/carlospolop/PEASS-ng
    - https://github.com/t3l3machus/hoaxshell
    - https://github.com/t3l3machus/Villain
    - https://github.com/HavocFramework/Havoc
    - https://github.com/1N3/Sn1per
    - https://github.com/Ne0nd0g/merlin
    - https://github.com/Pennyw0rth/NetExec/
author: Nasreddine Bencherchali (Nextron Systems), Georg Lauenstein (sure[secure])
date: 2023-01-03
modified: 2024-09-19
tags:
    - attack.execution
    - attack.resource-development
    - attack.t1587
logsource:
    product: linux
    category: process_creation
detection:
    selection_c2_frameworks:
        Image|endswith:
            - '/crackmapexec'
            - '/havoc'
            - '/merlin-agent'
            - '/merlinServer-Linux-x64'
            - '/msfconsole'
            - '/msfvenom'
            - '/ps-empire server'
            - '/ps-empire'
            - '/sliver-client'
            - '/sliver-server'
            - '/Villain.py'
    selection_c2_framework_cobaltstrike:
        Image|contains:
            - '/cobaltstrike'
            - '/teamserver'
    selection_scanners:
        Image|endswith:
            - '/autorecon'
            - '/httpx'
            - '/legion'
            - '/naabu'
            - '/netdiscover'
            - '/nuclei'
            - '/recon-ng'
    selection_scanners_sniper:
        Image|contains: '/sniper'
    selection_web_enum:
        Image|endswith:
            - '/dirb'
            - '/dirbuster'
            - '/eyewitness'
            - '/feroxbuster'
            - '/ffuf'
            - '/gobuster'
            - '/wfuzz'
            - '/whatweb'
    selection_web_vuln:
        Image|endswith:
            - '/joomscan'
            - '/nikto'
            - '/wpscan'
    selection_exploit_tools:
        Image|endswith:
            - '/aircrack-ng'
            - '/bloodhound-python'
            - '/bpfdos'
            - '/ebpfki'
            - '/evil-winrm'
            - '/hashcat'
            - '/hoaxshell.py'
            - '/hydra'
            - '/john'
            - '/ncrack'
            # default binary: https://github.com/Pennyw0rth/NetExec/releases/download/v1.0.0/nxc-ubuntu-latest
            - '/nxc-ubuntu-latest'
            - '/pidhide'
            - '/pspy32'
            - '/pspy32s'
            - '/pspy64'
            - '/pspy64s'
            - '/setoolkit'
            - '/sqlmap'
            - '/writeblocker'
    selection_linpeas:
        # covers: all linux versions listed here: https://github.com/carlospolop/PEASS-ng/releases
        Image|contains: '/linpeas'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high
```
