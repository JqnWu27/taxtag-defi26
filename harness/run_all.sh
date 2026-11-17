#!/usr/bin/env bash
# Runs every recording-side test of the artifact, one after the other, and
# prints a pass/fail summary. Needs the build of harness/bench_rec.sh
# (out/rec/c_rec.zkey, c_rec_js/c_rec.wasm, Verifier_c_rec.sol).
# Full logs: out/rec/logs/<name>.log. Fixtures are rewritten in fixtures/.
#
#   bash harness/run_all.sh            all tests (6 to 12 minutes)
#   bash harness/run_all.sh example    only the named ones
cd "$(dirname "$0")/.."
[ -f out/rec/c_rec.zkey ] || { echo "build first: bash harness/bench_rec.sh"; exit 1; }
mkdir -p out/rec/logs
TESTS="${*:-isold0 example liquidation withdrawal concurrency negative two_chains revoked_repay fixtures}"
fail=0
for t in $TESTS; do
  case $t in
    isold0)   script=harness/test_isold0.js ;;      # forged exclusion flag, circuit level
    fixtures) script=harness/check_fixtures.js ;;   # the JSON files alone, after the runs rewrote them
    *)        script=harness/run_$t.js ;;
  esac
  t0=$(date +%s)
  node $script > out/rec/logs/$t.log 2>&1
  code=$?
  t1=$(date +%s)
  summary=$(grep -E "^== .*(passed|FAILED|consistent)" out/rec/logs/$t.log | tail -1)
  nfail=$(grep -c "^FAIL" out/rec/logs/$t.log)
  if [ $code -ne 0 ] || [ "$nfail" != "0" ]; then fail=1; status="FAILED"; else status="ok"; fi
  printf "%-12s %-6s %4ss  %s\n" "$t" "$status" "$((t1 - t0))" "$summary"
done
[ $fail -eq 0 ] && echo "ALL RECORDING-SIDE TESTS PASSED" || echo "SOME TESTS FAILED (see out/rec/logs)"
exit $fail
