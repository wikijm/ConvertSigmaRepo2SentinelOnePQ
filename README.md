# ConvertSigmaRepo
Scripts stolen and heavily based on [rcegan/ConvertSigmaRepo2KQL](https://github.com/rcegan/ConvertSigmaRepo2KQL), played by GitHub Actions that converts Sigma rules to SentinelOne PowerQuery via PySigma.

## Usage

Firstly, modify the 'rules_directory' variable to reflect the location of your Sigma process creation rules. If using in CI/CD and you're cloning the Sigma repo in each time, you can leave this value as-is.

Next, modify the 'output_directory' to match whichever folder you want the rules to be dumped into. Expect over 1000+ results.

## Example
You can find an example of workflow here: [Example Workflow.md](Example Workflow.md)

## Thanks
Many thanks to:
- [@rcegan](https://github.com/rcegan) for [rcegan/ConvertSigmaRepo2KQL](https://github.com/rcegan/ConvertSigmaRepo2KQL)
- [@7RedViolin](https://github.com/7RedViolin) for [7RedViolin/pySigma-backend-sentinelone-pq)](https://github.com/7RedViolin/pySigma-backend-sentinelone-pq)
