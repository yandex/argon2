#!/bin/bash

set -e

declare -a platforms=("p4p" "mrm" "pnr" "nhm" "wsm" "snb" "ivb" "hsw" "bdw" "skx" "skl" "cnl" "knl" "slt" "slm" "glm")

for pl in "${platforms[@]}"
do
	echo "> Running test for $pl..."
	sde -"$pl" -- $1
done
