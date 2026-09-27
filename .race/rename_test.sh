#!/bin/sh
cd "$(dirname "$0")"
i=0; fail=0
while [ $i -lt 300 ]; do
  echo hello > a
  echo world > b
  mv -f a b          # rename over existing target
  out=$(cat b)
  if [ "$out" != "hello" ]; then
    echo "FAIL iter $i: got '$out' (errno info: $(ls b 2>&1))"
    fail=$((fail+1))
  fi
  i=$((i+1))
done
echo "failures: $fail"
