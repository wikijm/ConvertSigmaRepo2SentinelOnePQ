```sql
// Translated content (automatically translated on 25-10-2025 00:52:37):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/trufflehog" or ((tgt.process.cmdline contains " docker --image " or tgt.process.cmdline contains " Git " or tgt.process.cmdline contains " GitHub " or tgt.process.cmdline contains " Jira " or tgt.process.cmdline contains " Slack " or tgt.process.cmdline contains " Confluence " or tgt.process.cmdline contains " SharePoint " or tgt.process.cmdline contains " s3 " or tgt.process.cmdline contains " gcs ") and tgt.process.cmdline contains " --results=verified")))
```


# Original Sigma Rule:
```yaml
title: PUA - TruffleHog Execution - Linux
id: d7a650c4-226c-451e-948f-cc490db506aa
related:
    - id: 44030449-b0df-4c94-aae1-502359ab28ee
      type: similar
status: experimental
description: |
    Detects execution of TruffleHog, a tool used to search for secrets in different platforms like Git, Jira, Slack, SharePoint, etc. that could be used maliciously.
    While it is a legitimate tool, intended for use in CI pipelines and security assessments,
    It was observed in the Shai-Hulud malware campaign targeting npm packages to steal sensitive information.
references:
    - https://github.com/trufflesecurity/trufflehog
    - https://www.getsafety.com/blog-posts/shai-hulud-npm-attack
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-09-24
tags:
    - attack.discovery
    - attack.credential-access
    - attack.t1083
    - attack.t1552.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/trufflehog'
    selection_cli_platform:
        CommandLine|contains:
            - ' docker --image '
            - ' Git '
            - ' GitHub '
            - ' Jira '
            - ' Slack '
            - ' Confluence '
            - ' SharePoint '
            - ' s3 '
            - ' gcs '
    selection_cli_verified:
        CommandLine|contains: ' --results=verified'
    condition: selection_img or all of selection_cli_*
falsepositives:
    - Legitimate use of TruffleHog by security teams or developers.
level: medium
```
