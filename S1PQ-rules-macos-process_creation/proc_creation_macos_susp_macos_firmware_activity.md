```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path="/usr/sbin/firmwarepasswd" and (tgt.process.cmdline contains "setpasswd" or tgt.process.cmdline contains "full" or tgt.process.cmdline contains "delete" or tgt.process.cmdline contains "check")))
```


# Original Sigma Rule:
```yaml
title: Suspicious MacOS Firmware Activity
id: 7ed2c9f7-c59d-4c82-a7e2-f859aa676099
status: test
description: Detects when a user manipulates with Firmward Password on MacOS. NOTE - this command has been disabled on silicon-based apple computers.
references:
    - https://github.com/usnistgov/macos_security/blob/932a51f3e819dd3e02ebfcf3ef433cfffafbe28b/rules/os/os_firmware_password_require.yaml
    - https://www.manpagez.com/man/8/firmwarepasswd/
    - https://support.apple.com/guide/security/firmware-password-protection-sec28382c9ca/web
author: Austin Songer @austinsonger
date: 2021-09-30
modified: 2022-10-09
tags:
    - attack.impact
logsource:
    category: process_creation
    product: macos
detection:
    selection1:
        Image: '/usr/sbin/firmwarepasswd'
        CommandLine|contains:
            - 'setpasswd'
            - 'full'
            - 'delete'
            - 'check'
    condition: selection1
falsepositives:
    - Legitimate administration activities
level: medium
```
