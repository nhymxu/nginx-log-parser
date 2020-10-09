# nginx-log-parser
Simple script parse nginx access_log. Export to JSONL file.

## Run

### 1. Single log file
```shell script
python nginx-log-parser.py access.log.gz
```

### 2. Multi log file
Put all gz log file to logs folder
```shell script
./run.sh
```
