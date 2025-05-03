Below is an example GitHub workflow you could modify to grab rules and translate them daily:

```yml
name: Transform Sigma Windows Process Creation Events to S1PQ

on:
  workflow_dispatch:
 
  schedule:
    - cron: "0 0 * * *"  # Run once per day at midnight

jobs:
  run-python-script:
    runs-on: ubuntu-latest  # Change value from 'self-hosted' to 'ubuntu-latest' if you want to host it on Github.
    permissions:
      contents: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4.2.0
        
      - name: Set up Python
        uses: actions/setup-python@v4.7.1
        with:
          python-version: '3.12'
        
      - name: get sigma-cli
        run: |
          python -m pip install sigma-cli 
      
      - name: Install sigma-cli pipelines
        run: |
          sigma plugin install sentinelone-pq
        
      - name: Get Sigma repository
        run: |
          git clone https://github.com/SigmaHQ/sigma.git

      - name: Create destination folder 'S1PQ - Windows Process Creation'
        run: |
          mkdir -p "${{ github.workspace }}/S1PQ - Windows Process Creation"
          cd 'S1PQ - Windows Process Creation'
      
      - name: Run 'Sigma to S1PQ - Windows process event creation script'
        run: python sigma-to-s1pq-converter-win_process_create_markdown.py

      - name: Commit and push translated process creation rules
        uses: stefanzweifel/git-auto-commit-action@v5
```
