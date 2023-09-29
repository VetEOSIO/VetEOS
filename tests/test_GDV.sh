#!/bin/bash

directory="samples"
total_files=0
count=0

if [ ! -d "$directory" ]; then
  echo "Directory not found: $directory"
  exit 1
fi

for file in "$directory"/*; do
  if [[ -f "$file" && "$file" == *.wasm ]]; then
    echo "Analyzing file: $file"
    output=$(python3 main.py -f "$file" -g -d)
    total_files=$((total_files + 1))
    if [ "${output: -1}" == "1" ]; then
      count=$((count + 1))
    fi
  fi
done

echo "Total number of files analyzed: $total_files"
echo "Detected Groundhog Day Vulnerabilities: $count"
echo "Results are stored in ./results/"