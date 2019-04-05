#!/bin/bash

make test
make debug

set -e
for i in {1..10000}
	do ./test || exit 1
done
set e
