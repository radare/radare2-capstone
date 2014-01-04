#!/bin/sh
awk 'BEGIN{N=0}{if(N){N=($1+N)/2;} else{N=$1}}END{print "==> "N}'
