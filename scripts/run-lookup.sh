#!/bin/bash

log="$1"

for ((i=0; i < 10;))
do
    err=${log}.${i}.stderr
    echo "running #$i"
    sudo chrt -f 99 /usr/bin/time -f \
        "\n***\ntime: %E\ncontext switches: %c\nwaits: %w" \
        tools/depmod -a > ${log}.$i 2>$err
    [[ ! -z "$(grep 'context switches: 0' $err)" ]] && ((i++))
done

echo "consolidating in $log"
rm ${log}.0*
cat "$log".[1-9] | scripts/parse-timing > $log
rm ${log}.*
