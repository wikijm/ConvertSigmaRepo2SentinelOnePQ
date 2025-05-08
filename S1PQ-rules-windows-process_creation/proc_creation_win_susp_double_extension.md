```sql
// Translated content (automatically translated on 08-05-2025 02:02:58):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains ".doc.exe" or tgt.process.image.path contains ".docx.exe" or tgt.process.image.path contains ".xls.exe" or tgt.process.image.path contains ".xlsx.exe" or tgt.process.image.path contains ".ppt.exe" or tgt.process.image.path contains ".pptx.exe" or tgt.process.image.path contains ".rtf.exe" or tgt.process.image.path contains ".pdf.exe" or tgt.process.image.path contains ".txt.exe" or tgt.process.image.path contains "      .exe" or tgt.process.image.path contains "______.exe" or tgt.process.image.path contains ".doc.js" or tgt.process.image.path contains ".docx.js" or tgt.process.image.path contains ".xls.js" or tgt.process.image.path contains ".xlsx.js" or tgt.process.image.path contains ".ppt.js" or tgt.process.image.path contains ".pptx.js" or tgt.process.image.path contains ".rtf.js" or tgt.process.image.path contains ".pdf.js" or tgt.process.image.path contains ".txt.js") and (tgt.process.cmdline contains ".doc.exe" or tgt.process.cmdline contains ".docx.exe" or tgt.process.cmdline contains ".xls.exe" or tgt.process.cmdline contains ".xlsx.exe" or tgt.process.cmdline contains ".ppt.exe" or tgt.process.cmdline contains ".pptx.exe" or tgt.process.cmdline contains ".rtf.exe" or tgt.process.cmdline contains ".pdf.exe" or tgt.process.cmdline contains ".txt.exe" or tgt.process.cmdline contains "      .exe" or tgt.process.cmdline contains "______.exe" or tgt.process.cmdline contains ".doc.js" or tgt.process.cmdline contains ".docx.js" or tgt.process.cmdline contains ".xls.js" or tgt.process.cmdline contains ".xlsx.js" or tgt.process.cmdline contains ".ppt.js" or tgt.process.cmdline contains ".pptx.js" or tgt.process.cmdline contains ".rtf.js" or tgt.process.cmdline contains ".pdf.js" or tgt.process.cmdline contains ".txt.js")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Double Extension File Execution
id: 1cdd9a09-06c9-4769-99ff-626e2b3991b8
related:
    - id: 5e6a80c8-2d45-4633-9ef4-fa2671a39c5c # ParentImage/ParentCommandLine
      type: similar
status: stable
description: Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns
references:
    - https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html
    - https://twitter.com/blackorbird/status/1140519090961825792
author: Florian Roth (Nextron Systems), @blu3_team (idea), Nasreddine Bencherchali (Nextron Systems)
date: 2019-06-26
modified: 2023-02-28
tags:
    - attack.initial-access
    - attack.t1566.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '.doc.exe'
            - '.docx.exe'
            - '.xls.exe'
            - '.xlsx.exe'
            - '.ppt.exe'
            - '.pptx.exe'
            - '.rtf.exe'
            - '.pdf.exe'
            - '.txt.exe'
            - '      .exe'
            - '______.exe'
            - '.doc.js'
            - '.docx.js'
            - '.xls.js'
            - '.xlsx.js'
            - '.ppt.js'
            - '.pptx.js'
            - '.rtf.js'
            - '.pdf.js'
            - '.txt.js'
        CommandLine|contains:
            - '.doc.exe'
            - '.docx.exe'
            - '.xls.exe'
            - '.xlsx.exe'
            - '.ppt.exe'
            - '.pptx.exe'
            - '.rtf.exe'
            - '.pdf.exe'
            - '.txt.exe'
            - '      .exe'
            - '______.exe'
            - '.doc.js'
            - '.docx.js'
            - '.xls.js'
            - '.xlsx.js'
            - '.ppt.js'
            - '.pptx.js'
            - '.rtf.js'
            - '.pdf.js'
            - '.txt.js'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
