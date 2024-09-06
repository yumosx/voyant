#!/bin/bash

if [ -z "$1" ]; then
    echo "Error: no tracepoint string input;"
    exit 1
fi

echo "probe $1 {" > prog.y
echo "}" >> prog.y

echo "the program has been generated:"
cat prog.y