```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains ".doc.lnk" or src.process.image.path contains ".docx.lnk" or src.process.image.path contains ".xls.lnk" or src.process.image.path contains ".xlsx.lnk" or src.process.image.path contains ".ppt.lnk" or src.process.image.path contains ".pptx.lnk" or src.process.image.path contains ".rtf.lnk" or src.process.image.path contains ".pdf.lnk" or src.process.image.path contains ".txt.lnk" or src.process.image.path contains ".doc.js" or src.process.image.path contains ".docx.js" or src.process.image.path contains ".xls.js" or src.process.image.path contains ".xlsx.js" or src.process.image.path contains ".ppt.js" or src.process.image.path contains ".pptx.js" or src.process.image.path contains ".rtf.js" or src.process.image.path contains ".pdf.js" or src.process.image.path contains ".txt.js") or (src.process.cmdline contains ".doc.lnk" or src.process.cmdline contains ".docx.lnk" or src.process.cmdline contains ".xls.lnk" or src.process.cmdline contains ".xlsx.lnk" or src.process.cmdline contains ".ppt.lnk" or src.process.cmdline contains ".pptx.lnk" or src.process.cmdline contains ".rtf.lnk" or src.process.cmdline contains ".pdf.lnk" or src.process.cmdline contains ".txt.lnk" or src.process.cmdline contains ".doc.js" or src.process.cmdline contains ".docx.js" or src.process.cmdline contains ".xls.js" or src.process.cmdline contains ".xlsx.js" or src.process.cmdline contains ".ppt.js" or src.process.cmdline contains ".pptx.js" or src.process.cmdline contains ".rtf.js" or src.process.cmdline contains ".pdf.js" or src.process.cmdline contains ".txt.js")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Parent Double Extension File Execution
id: 5e6a80c8-2d45-4633-9ef4-fa2671a39c5c
related:
    - id: 1cdd9a09-06c9-4769-99ff-626e2b3991b8 # Image/CommandLine
      type: derived
status: test
description: Detect execution of suspicious double extension files in ParentCommandLine
references:
    - https://www.virustotal.com/gui/file/7872d8845a332dce517adae9c3389fde5313ff2fed38c2577f3b498da786db68/behavior
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/bluebottle-banks-targeted-africa
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-06
modified: 2023-02-28
tags:
    - attack.defense-evasion
    - attack.t1036.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - ParentImage|endswith:
              - '.doc.lnk'
              - '.docx.lnk'
              - '.xls.lnk'
              - '.xlsx.lnk'
              - '.ppt.lnk'
              - '.pptx.lnk'
              - '.rtf.lnk'
              - '.pdf.lnk'
              - '.txt.lnk'
              - '.doc.js'
              - '.docx.js'
              - '.xls.js'
              - '.xlsx.js'
              - '.ppt.js'
              - '.pptx.js'
              - '.rtf.js'
              - '.pdf.js'
              - '.txt.js'
        - ParentCommandLine|contains:
              - '.doc.lnk'
              - '.docx.lnk'
              - '.xls.lnk'
              - '.xlsx.lnk'
              - '.ppt.lnk'
              - '.pptx.lnk'
              - '.rtf.lnk'
              - '.pdf.lnk'
              - '.txt.lnk'
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
level: high
```
