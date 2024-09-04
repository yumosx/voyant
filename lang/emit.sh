#!/bin/bash

echo "Place input a tracpoint string for program:"
read trace

if [ -z "$trace" ]; then
    echo "Error: no tracepoint string input;"
    exit 1
fi

echo "probe $trace {" > prog.y
echo "}" >> prog.y

echo "the program has been generated:"
cat prog.y