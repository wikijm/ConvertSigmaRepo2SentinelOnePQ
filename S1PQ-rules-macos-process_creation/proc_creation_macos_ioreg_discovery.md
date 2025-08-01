```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/ioreg" or tgt.process.cmdline contains "ioreg") and (tgt.process.cmdline contains "-l" or tgt.process.cmdline contains "-c") and (tgt.process.cmdline contains "AppleAHCIDiskDriver" or tgt.process.cmdline contains "IOPlatformExpertDevice" or tgt.process.cmdline contains "Oracle" or tgt.process.cmdline contains "Parallels" or tgt.process.cmdline contains "USB Vendor Name" or tgt.process.cmdline contains "VirtualBox" or tgt.process.cmdline contains "VMware")))
```


# Original Sigma Rule:
```yaml
title: System Information Discovery Using Ioreg
id: 2d5e7a8b-f484-4a24-945d-7f0efd52eab0
status: test
description: |
    Detects the use of "ioreg" which will show I/O Kit registry information.
    This process is used for system information discovery.
    It has been observed in-the-wild by calling this process directly or using bash and grep to look for specific strings.
references:
    - https://www.virustotal.com/gui/file/0373d78db6c3c0f6f6dcc409821bf89e1ad8c165d6f95c5c80ecdce2219627d7/behavior
    - https://www.virustotal.com/gui/file/4ffdc72d1ff1ee8228e31691020fc275afd1baee5a985403a71ca8c7bd36e2e4/behavior
    - https://www.virustotal.com/gui/file/5907d59ec1303cfb5c0a0f4aaca3efc0830707d86c732ba6b9e842b5730b95dc/behavior
    - https://www.trendmicro.com/en_ph/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-12-20
modified: 2024-01-02
tags:
    - attack.discovery
    - attack.t1082
logsource:
    product: macos
    category: process_creation
detection:
    # Examples:
    #   /bin/bash /bin/sh -c ioreg -l | grep -e 'VirtualBox' -e 'Oracle' -e 'VMware' -e 'Parallels' | wc -l
    #   /usr/sbin/ioreg ioreg -rd1 -w0 -c AppleAHCIDiskDriver
    #   /bin/bash /bin/sh -c ioreg -l | grep -e 'USB Vendor Name'
    #   ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformSerialNumber/ { split($0, line, \"\\\"\"); printf(\"%s\", line[4]); }
    selection_img:
        - Image|endswith: '/ioreg'
        - CommandLine|contains: 'ioreg'
    selection_cmd1:
        CommandLine|contains:
            - '-l'
            - '-c'
    selection_cmd2:
        CommandLine|contains:
            - 'AppleAHCIDiskDriver'
            - 'IOPlatformExpertDevice'
            - 'Oracle'
            - 'Parallels'
            - 'USB Vendor Name'
            - 'VirtualBox'
            - 'VMware'
    condition: all of selection_*
falsepositives:
    - Legitimate administrative activities
level: medium
```
