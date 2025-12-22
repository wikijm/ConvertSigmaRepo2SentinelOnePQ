```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "      .exe" or tgt.process.image.path contains "______.exe" or tgt.process.image.path contains ".doc.exe" or tgt.process.image.path contains ".doc.js" or tgt.process.image.path contains ".docx.exe" or tgt.process.image.path contains ".docx.js" or tgt.process.image.path contains ".gif.exe" or tgt.process.image.path contains ".jpeg.exe" or tgt.process.image.path contains ".jpg.exe" or tgt.process.image.path contains ".mkv.exe" or tgt.process.image.path contains ".mov.exe" or tgt.process.image.path contains ".mp3.exe" or tgt.process.image.path contains ".mp4.exe" or tgt.process.image.path contains ".pdf.exe" or tgt.process.image.path contains ".pdf.js" or tgt.process.image.path contains ".png.exe" or tgt.process.image.path contains ".ppt.exe" or tgt.process.image.path contains ".ppt.js" or tgt.process.image.path contains ".pptx.exe" or tgt.process.image.path contains ".pptx.js" or tgt.process.image.path contains ".rtf.exe" or tgt.process.image.path contains ".rtf.js" or tgt.process.image.path contains ".svg.exe" or tgt.process.image.path contains ".txt.exe" or tgt.process.image.path contains ".txt.js" or tgt.process.image.path contains ".xls.exe" or tgt.process.image.path contains ".xls.js" or tgt.process.image.path contains ".xlsx.exe" or tgt.process.image.path contains ".xlsx.js" or tgt.process.image.path contains "⠀⠀⠀⠀⠀⠀.exe") and (tgt.process.cmdline contains "      .exe" or tgt.process.cmdline contains "______.exe" or tgt.process.cmdline contains ".doc.exe" or tgt.process.cmdline contains ".doc.js" or tgt.process.cmdline contains ".docx.exe" or tgt.process.cmdline contains ".docx.js" or tgt.process.cmdline contains ".gif.exe" or tgt.process.cmdline contains ".jpeg.exe" or tgt.process.cmdline contains ".jpg.exe" or tgt.process.cmdline contains ".mkv.exe" or tgt.process.cmdline contains ".mov.exe" or tgt.process.cmdline contains ".mp3.exe" or tgt.process.cmdline contains ".mp4.exe" or tgt.process.cmdline contains ".pdf.exe" or tgt.process.cmdline contains ".pdf.js" or tgt.process.cmdline contains ".png.exe" or tgt.process.cmdline contains ".ppt.exe" or tgt.process.cmdline contains ".ppt.js" or tgt.process.cmdline contains ".pptx.exe" or tgt.process.cmdline contains ".pptx.js" or tgt.process.cmdline contains ".rtf.exe" or tgt.process.cmdline contains ".rtf.js" or tgt.process.cmdline contains ".svg.exe" or tgt.process.cmdline contains ".txt.exe" or tgt.process.cmdline contains ".txt.js" or tgt.process.cmdline contains ".xls.exe" or tgt.process.cmdline contains ".xls.js" or tgt.process.cmdline contains ".xlsx.exe" or tgt.process.cmdline contains ".xlsx.js" or tgt.process.cmdline contains "⠀⠀⠀⠀⠀⠀.exe")))
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
    - https://cloud.google.com/blog/topics/threat-intelligence/cybercriminals-weaponize-fake-ai-websites
author: Florian Roth (Nextron Systems), @blu3_team (idea), Nasreddine Bencherchali (Nextron Systems)
date: 2019-06-26
modified: 2025-05-30
tags:
    - attack.initial-access
    - attack.t1566.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '      .exe'
            - '______.exe'
            - '.doc.exe'
            - '.doc.js'
            - '.docx.exe'
            - '.docx.js'
            - '.gif.exe'
            - '.jpeg.exe'
            - '.jpg.exe'
            - '.mkv.exe'
            - '.mov.exe'
            - '.mp3.exe'
            - '.mp4.exe'
            - '.pdf.exe'
            - '.pdf.js'
            - '.png.exe'
            - '.ppt.exe'
            - '.ppt.js'
            - '.pptx.exe'
            - '.pptx.js'
            - '.rtf.exe'
            - '.rtf.js'
            - '.svg.exe'
            - '.txt.exe'
            - '.txt.js'
            - '.xls.exe'
            - '.xls.js'
            - '.xlsx.exe'
            - '.xlsx.js'
            - '⠀⠀⠀⠀⠀⠀.exe' # Unicode Space Character: Braille Pattern Blank (Unicode: U+2800)
        CommandLine|contains:
            - '      .exe'
            - '______.exe'
            - '.doc.exe'
            - '.doc.js'
            - '.docx.exe'
            - '.docx.js'
            - '.gif.exe'
            - '.jpeg.exe'
            - '.jpg.exe'
            - '.mkv.exe'
            - '.mov.exe'
            - '.mp3.exe'
            - '.mp4.exe'
            - '.pdf.exe'
            - '.pdf.js'
            - '.png.exe'
            - '.ppt.exe'
            - '.ppt.js'
            - '.pptx.exe'
            - '.pptx.js'
            - '.rtf.exe'
            - '.rtf.js'
            - '.svg.exe'
            - '.txt.exe'
            - '.txt.js'
            - '.xls.exe'
            - '.xls.js'
            - '.xlsx.exe'
            - '.xlsx.js'
            - '⠀⠀⠀⠀⠀⠀.exe' # Unicode Space Character: Braille Pattern Blank (Unicode: U+2800)
    condition: selection
falsepositives:
    - Unknown
level: high
```
