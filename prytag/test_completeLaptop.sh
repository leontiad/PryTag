#!/bin/bash

function test {
    if [ "$#" -ne 3 ]; then
	echo "Illegal number of parameters"
	echo "usage $0  <size_of_N> <size_of_L> <number_of_users>"
	exit -1
    fi

    fraw="./results/complete_raw_n$1_l$2_u$3_$( date '+%Y-%m-%d_%H%M%S' )"
    
    echo "Output raw written on $fraw"
    ./demo_centralised/demo -v -n $1 -l $2 -u $3 > $fraw
}

for k in 2048 4096 ; do for j in 10 100 1000 ; do for i in 500 1000 10000 100000  ; do test $k $j $i; done; done; done;
#for k in 4096 ; do for j in 10 100 1000 ; do for i in 1000000  ; do test $k $j $i; done; done; done;
