```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/openssl" and (tgt.process.cmdline contains "/Volumes/" and tgt.process.cmdline contains "enc" and tgt.process.cmdline contains "-base64" and tgt.process.cmdline contains " -d ")))
```


# Original Sigma Rule:
```yaml
title: Payload Decoded and Decrypted via Built-in Utilities
id: 234dc5df-40b5-49d1-bf53-0d44ce778eca
status: test
description: Detects when a built-in utility is used to decode and decrypt a payload after a macOS disk image (DMG) is executed. Malware authors may attempt to evade detection and trick users into executing malicious code by encoding and encrypting their payload and placing it in a disk image file. This behavior is consistent with adware or malware families such as Bundlore and Shlayer.
references:
    - https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-5d42c3d772e04f1e8d0eb60f5233bc79def1ea73105a2d8822f44164f77ef823
author: Tim Rauch (rule), Elastic (idea)
date: 2022-10-17
tags:
    - attack.t1059
    - attack.t1204
    - attack.execution
    - attack.t1140
    - attack.defense-evasion
    - attack.s0482
    - attack.s0402
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/openssl'
        CommandLine|contains|all:
            - '/Volumes/'
            - 'enc'
            - '-base64'
            - ' -d '
    condition: selection
falsepositives:
    - Unknown
level: medium
```
