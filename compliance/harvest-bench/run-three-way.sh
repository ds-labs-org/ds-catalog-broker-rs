#!/usr/bin/env bash
# Three-way harvesting benchmark driver. Same conditions as
# run-harvest-bench.sh (2026-08-27/28): two EDC 0.18.0 participants
# (3 + 7 datasets) crawled every 5 s while the target's own catalog
# endpoint takes 20 constant VUs for 30 s from k6; RSS/CPU sampled at 1 s.
#
# Targets (run in this order, ROUNDS times):
#   broker-old        the broker at the commit that produced the last report
#   broker-main       the broker at current head, default config
#   broker-main-nofilter  same binary, policyFilterRunWhenOauth2Disabled=false
#   edc-rc5           Eclipse EDC federated catalog 1.0.0-RC5
#
# Env: HB (this directory), BIN_OLD, BIN_MAIN, OLD_TOML (the old build's
#      participants.toml), EDC_DIR (edc-fedcat-runtime), OUT, ROUNDS (default 3),
#      TARGETS (subset of the four labels), EDC_API (v3 for EDC <= 0.18, v4 for
#      1.0.0-RC5), EDC_QUERYSPEC_BODY (v4 needs an @vocab context; see the report).
# Report: ../harvest-benchmark-2026-11-01.md
set -uo pipefail
: "${HB:?}" "${BIN_OLD:?}" "${BIN_MAIN:?}" "${OLD_TOML:?}" "${EDC_DIR:?}" "${OUT:?}"
ROUNDS="${ROUNDS:-3}"
DEFAULT_QS='{"@type":"https://w3id.org/edc/v0.0.1/ns/QuerySpec"}'
export EDC_QUERYSPEC_BODY="${EDC_QUERYSPEC_BODY:-$DEFAULT_QS}"
FIXTURE_DIR="$HB/../crawler-edc-fixture"
mkdir -p "$OUT" "$FIXTURE_DIR/logs" "$EDC_DIR/logs"

D_BASE=19201; E_BASE=19301; EDC_BASE=19401; RUST_ADDR="127.0.0.1:19501"
D_DSP="http://127.0.0.1:$((D_BASE+20))/api/dsp/2025-1"
E_DSP="http://127.0.0.1:$((E_BASE+20))/api/dsp/2025-1"
EDC_MGMT_PORT=$((EDC_BASE+10))
EDC_URL="http://127.0.0.1:$EDC_MGMT_PORT/api/management/${EDC_API:-v3}/catalogs/request"
RUST_URL="http://$RUST_ADDR/catalog"
PIDS=()
log() { echo "[three-way] $*" >&2; }
pid_on() { ss -tlnp 2>/dev/null | grep ":$1 " | grep -oP 'pid=\K[0-9]+' | head -1; }
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  sleep 3
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
  ss -tlnp 2>/dev/null | grep -E ":19[2-5][0-9]{2} " || log "ports clean"
}
trap cleanup EXIT

( cd "$FIXTURE_DIR" && ./gradlew --console=plain printClasspath >/dev/null ) || { log "fixture build failed"; exit 1; }
( cd "$FIXTURE_DIR" && INSTANCE_NAME=harvest-d BASE_PORT=$D_BASE FIXTURE_PARTICIPANT_ID=HARVEST-D \
    FIXTURE_ASSET_IDS="HARVEST-D-01,HARVEST-D-02,HARVEST-D-03" nohup ./run-instance.sh >"$OUT/harvest-d.out" 2>&1 & )
( cd "$FIXTURE_DIR" && INSTANCE_NAME=harvest-e BASE_PORT=$E_BASE FIXTURE_PARTICIPANT_ID=HARVEST-E \
    FIXTURE_ASSET_IDS="HARVEST-E-01,HARVEST-E-02,HARVEST-E-03,HARVEST-E-04,HARVEST-E-05,HARVEST-E-06,HARVEST-E-07" nohup ./run-instance.sh >"$OUT/harvest-e.out" 2>&1 & )
sleep 12
DP=$(pid_on $((D_BASE+20))); EP=$(pid_on $((E_BASE+20)))
[ -z "$DP" ] || [ -z "$EP" ] && { log "participants did not start"; exit 1; }
PIDS+=("$DP" "$EP")
log "participants up: $DP $EP"

run_load() { # label url kind(edc|rust) pid dir
  local label=$1 url=$2 kind=$3 pid=$4 dir=$5
  python3 "$HB/check_catalog.py" "$kind" "$url" >"$dir/$label-correct-early.txt" 2>&1; echo $? >"$dir/$label-correct-early.rc"
  bash "$HB/sample-rss-cpu.sh" "$pid" 35 "$dir/$label-rss.csv" & local sp=$!
  if [ "$kind" = edc ]; then
    k6 run --summary-export "$dir/$label-k6.json" -e TARGET_URL="$url" \
      -e BODY="$EDC_QUERYSPEC_BODY" "$HB/catalog-request.k6.js" >"$dir/$label-k6.log" 2>&1
  else
    k6 run --summary-export "$dir/$label-k6.json" -e TARGET_URL="$url" -e METHOD=GET "$HB/catalog-request.k6.js" >"$dir/$label-k6.log" 2>&1
  fi
  python3 "$HB/check_catalog.py" "$kind" "$url" >"$dir/$label-correct-late.txt" 2>&1; echo $? >"$dir/$label-correct-late.rc"
  wait "$sp" 2>/dev/null
}
stop_pid() { kill "$1" 2>/dev/null; sleep 3; kill -9 "$1" 2>/dev/null; sleep 1; }

start_rust() { # label bin mode
  local label=$1 bin=$2 mode=$3 cfg="$OUT/cfg-$1-$ROUND"
  mkdir -p "$cfg"
  case $mode in
   old)
    ( HTTP_API_ADDR="$RUST_ADDR" CRAWLER_CONFIG_PATH="$OLD_TOML" nohup "$bin" >"$DIR/$label.log" 2>&1 & ) ;;
   main|nofilter)
    cat > "$cfg/config_graph.ttl" <<TTL
@prefix broker: <https://catalog-broker.ds-labs.org/ontologies/config#> .
<urn:ds-catalog-broker:config> a broker:BrokerConfig ;
    broker:httpApiAddr "$RUST_ADDR" ;
    broker:crawlIntervalSecs 5 ;
$( [ $mode = nofilter ] && echo '    broker:policyFilterRunWhenOauth2Disabled false ;' )
    broker:participant <urn:harvest-bench:d>, <urn:harvest-bench:e> .
TTL
    cat "$HB/participants.ttl" >> "$cfg/config_graph.ttl"
    ( CONFIG_STORE_PATH="$cfg" nohup "$bin" >"$DIR/$label.log" 2>&1 & ) ;;
  esac
  sleep 6
  RPID=$(pid_on 19501)
  [ -z "$RPID" ] && { log "$label did not start"; tail -20 "$DIR/$label.log"; return 1; }
  PIDS+=("$RPID"); sleep 8
}

for ROUND in $(seq 1 "$ROUNDS"); do
  DIR="$OUT/round-$ROUND"; mkdir -p "$DIR"
  for t in ${TARGETS:-broker-old broker-main broker-main-nofilter edc-rc5}; do
    log "round $ROUND: $t"
    case $t in
      broker-old) start_rust $t "$BIN_OLD" old && { run_load $t "$RUST_URL" rust "$RPID" "$DIR"; stop_pid "$RPID"; } ;;
      broker-main) start_rust $t "$BIN_MAIN" main && { run_load $t "$RUST_URL" rust "$RPID" "$DIR"; stop_pid "$RPID"; } ;;
      broker-main-nofilter) start_rust $t "$BIN_MAIN" nofilter && { run_load $t "$RUST_URL" rust "$RPID" "$DIR"; stop_pid "$RPID"; } ;;
      edc-rc5)
        ( cd "$EDC_DIR" && BASE_PORT=$EDC_BASE CRAWL_PERIOD_SECONDS=5 \
          HARVEST_TARGET_NODES="harvest-d=Harvest D=$D_DSP;harvest-e=Harvest E=$E_DSP" \
          nohup ./run-fedcat-crawler.sh >"$DIR/$t.out" 2>&1 & )
        sleep 10; FP=$(pid_on $EDC_MGMT_PORT)
        if [ -z "$FP" ]; then log "edc did not start"; tail -30 "$EDC_DIR/logs/fedcat-crawler.log"; continue; fi
        PIDS+=("$FP"); sleep 10
        run_load $t "$EDC_URL" edc "$FP" "$DIR"; stop_pid "$FP"
        cp "$EDC_DIR/logs/fedcat-crawler.log" "$DIR/$t-crawler.log" 2>/dev/null; : > "$EDC_DIR/logs/fedcat-crawler.log" ;;
    esac
  done
done
log "DONE"
