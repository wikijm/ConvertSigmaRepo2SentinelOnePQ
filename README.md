# ConvertSigmaRepo
Scripts stolen and heavily based on [rcegan/ConvertSigmaRepo2KQL](https://github.com/rcegan/ConvertSigmaRepo2KQL), played by GitHub Actions that converts Sigma rules to SentinelOne PowerQuery via PySigma.

## Usage

Firstly, modify the 'rules_directory' variable to reflect the location of your Sigma process creation rules. If using in CI/CD and you're cloning the Sigma repo in each time, you can leave this value as-is.

Next, modify the 'output_directory' to match whichever folder you want the rules to be dumped into. Expect over 1000+ results.

## Example
For GitHub Workflow, you can find an example of workflow here: [Example Workflow.md](Example Workflow.md)

To see what result [sigma-to-s1pq-converter-win_process_create_markdown.py](sigma-to-s1pq-converter-win_process_create_markdown.py) is generating, please look at [SentinelOne_PQ - Windows Process Creation/proc_creation_win_addinutil_uncommon_child_process.md](SentinelOne_PQ - Windows Process Creation/proc_creation_win_addinutil_uncommon_child_process.md)
![image](https://github.com/user-attachments/assets/ca6af8ff-f15b-4142-a0e4-17e72bb619b4)


## Thanks
Many thanks to:
- [@rcegan](https://github.com/rcegan) for [rcegan/ConvertSigmaRepo2KQL](https://github.com/rcegan/ConvertSigmaRepo2KQL)
- [@7RedViolin](https://github.com/7RedViolin) for [7RedViolin/pySigma-backend-sentinelone-pq)](https://github.com/7RedViolin/pySigma-backend-sentinelone-pq)
