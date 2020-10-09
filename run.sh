#!/bin/bash

. .venv/bin/activate

for i in logs/*.gz; do
  [ -f "$i" ]
  echo "$i"
  python nginx-log-parser.py "$i"
done
