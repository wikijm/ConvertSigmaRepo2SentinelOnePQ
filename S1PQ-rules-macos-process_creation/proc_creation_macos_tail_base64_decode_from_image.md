```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/bash" and (tgt.process.cmdline contains "tail" and tgt.process.cmdline contains "-c") and (tgt.process.cmdline contains "base64" and tgt.process.cmdline contains "-d" and tgt.process.cmdline contains ">") and (tgt.process.cmdline contains ".avif" or tgt.process.cmdline contains ".gif" or tgt.process.cmdline contains ".jfif" or tgt.process.cmdline contains ".jpeg" or tgt.process.cmdline contains ".jpg" or tgt.process.cmdline contains ".pjp" or tgt.process.cmdline contains ".pjpeg" or tgt.process.cmdline contains ".png" or tgt.process.cmdline contains ".svg" or tgt.process.cmdline contains ".webp")))
```


# Original Sigma Rule:
```yaml
title: Potential Base64 Decoded From Images
id: 09a910bf-f71f-4737-9c40-88880ba5913d
status: test
description: |
    Detects the use of tail to extract bytes at an offset from an image and then decode the base64 value to create a new file with the decoded content. The detected execution is a bash one-liner.
references:
    - https://www.virustotal.com/gui/file/16bafdf741e7a13137c489f3c8db1334f171c7cb13b62617d691b0a64783cc48/behavior
    - https://www.virustotal.com/gui/file/483fafc64a2b84197e1ef6a3f51e443f84dc5742602e08b9e8ec6ad690b34ed0/behavior
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-12-20
tags:
    - attack.defense-evasion
    - attack.t1140
logsource:
    product: macos
    category: process_creation
detection:
    # Example:  /bin/bash sh -c tail -c +21453 '/Volumes/Installer/Installer.app/Contents/Resources/workout-logo.jpeg' | base64 --decode > /tmp/54A0A2CD-FAD1-4D4D-AAF5-5266F6344ABE.zip
    # VT Query: 'behavior_processes:"tail" (behavior_processes:"jpeg" or behavior_processes:"jpg" or behavior_processes:"png" or behavior_processes:"gif") behavior_processes:"base64" behavior_processes:"--decode >" and tag:dmg'
    selection_image:
        Image|endswith: '/bash'
    selection_view:
        CommandLine|contains|all:
            - 'tail'
            - '-c'
    selection_b64:
        CommandLine|contains|all:
            - 'base64'
            - '-d' # Also covers "--decode"
            - '>'
    selection_files:
        CommandLine|contains:
            - '.avif'
            - '.gif'
            - '.jfif'
            - '.jpeg'
            - '.jpg'
            - '.pjp'
            - '.pjpeg'
            - '.png'
            - '.svg'
            - '.webp'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
