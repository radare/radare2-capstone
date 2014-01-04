#!/bin/sh
F=/bin/ksh

for b in 99 999 9999 59999 ; do
	for a in x86 x86.cs ; do
		for c in 1 2 3 ; do
			printf "==> $a $b "
			echo "50?t pi $b" | r2 -qn -a $a "$F" >/dev/null 2> $a.$b.txt
			./med.sh < $a.$b.txt
			rm -f $a.$b.txt
		done
	done
done
