#!/bin/bash
input=$(jq .[] "$1")
while IFS= read -r line
do
  new_line="${line:1:${#line}-2}"
  curl -X GET http://localhost:5000/download/"$new_line" > ./"$new_line"
done <<< "$input"