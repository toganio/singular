#!/usr/bin/env bash
# End to end, with nothing faked: a ledger node, an OCI registry, and the runtime image.
#
#   singular/hosting/e2e.sh [image]          (default image: singular-runtime:dev, built beforehand)
#
# 1. owner side: create an agent, export it for hosting (--move), push the capsule to the registry
# 2. host side:  start the image with only a pinned capsule reference and a secrets file
# Plain http between containers on a private docker network, so the insecure-ledger switch is set.
# 3. check:      the ledger shows the run lease; `docker stop` seals and releases it; a restart reuses the volume
set -euo pipefail
IMAGE="${1:-singular-runtime:dev}"
RUN_ID="sng-e2e-$$"
NET="$RUN_ID"
WORK="$(mktemp -d)"
chmod 755 "$WORK"
REGISTRY_IMAGE="${REGISTRY_IMAGE:-registry:2}"
COMMAND="${E2E_COMMAND:-hermes gateway run}"

cleanup() {
  docker rm -f "$RUN_ID-agent" "$RUN_ID-copy" "$RUN_ID-ledger" "$RUN_ID-registry" >/dev/null 2>&1 || true
  docker volume rm "$RUN_ID-home" "$RUN_ID-home-bo" "$RUN_ID-home-copy" "$RUN_ID-chain" >/dev/null 2>&1 || true
  docker rmi "$RUN_ID-bo:v1" "$RUN_ID-bo:v2" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
in_image() { docker run --rm --network "$NET" -v "$WORK:/work" --user "$(id -u):$(id -g)" -e HOME=/work \
               -e SINGULAR_REGISTRY_INSECURE=1 -e SINGULAR_ALLOW_INSECURE_LEDGER=1 --entrypoint "$1" "$IMAGE" "${@:2}"; }
lease() { in_image python -c "import sys; from singular.ledger.client import HttpLedger
a = HttpLedger('http://ledger:8765').get_agent(sys.argv[1]); print('held' if a['lease'] else 'free')" "$AGENT_ID"; }

docker network create "$NET" >/dev/null
docker volume create "$RUN_ID-chain" >/dev/null

step "ledger node and registry"
docker run --rm -v "$RUN_ID-chain:/chain" --user root --entrypoint chown "$IMAGE" agent /chain
docker run --rm -v "$RUN_ID-chain:/chain" -e SINGULAR_VALIDATOR_PASSPHRASE=validator-pass-e2e --entrypoint singular "$IMAGE" \
  ledger init --db /chain/chain.db --validator-key /chain/validator.keystore.json --name e2e
docker run -d --name "$RUN_ID-ledger" --network "$NET" --network-alias ledger -v "$RUN_ID-chain:/chain" \
  -e SINGULAR_VALIDATOR_PASSPHRASE=validator-pass-e2e --entrypoint singular "$IMAGE" \
  ledger serve --db /chain/chain.db --validator-key /chain/validator.keystore.json --host 0.0.0.0 --port 8765 >/dev/null
docker run -d --name "$RUN_ID-registry" --network "$NET" --network-alias registry "$REGISTRY_IMAGE" >/dev/null
for _ in $(seq 60); do
  in_image python -c "import urllib.request as u; u.urlopen('http://ledger:8765/info'); u.urlopen('http://registry:5000/v2/')" \
    >/dev/null 2>&1 && break
  sleep 1
done

step "owner: create the agent, export it for hosting, push the capsule"
mkdir -p "$WORK/home"
printf 'You are Ada, a contracts assistant.\n' > "$WORK/home/SOUL.md"
mkdir -p "$WORK/home/memories" && printf -- '- prefers short answers\n' > "$WORK/home/memories/MEMORY.md"
export_env=(-e SINGULAR_OWNER_PASSPHRASE=owner-pass-e2e -e SINGULAR_PASSPHRASE=agent-pass-e2e
            -e SINGULAR_CAPSULE_PASSPHRASE=capsule-pass-e2e)
docker run --rm --network "$NET" -v "$WORK:/work" --user "$(id -u):$(id -g)" -e HOME=/work "${export_env[@]}" \
  -e SINGULAR_REGISTRY_INSECURE=1 -e SINGULAR_ALLOW_INSECURE_LEDGER=1 --entrypoint sh "$IMAGE" -c '
    set -e
    singular owner-new --out /work/owner.keystore.json >/dev/null
    singular init --owner-key /work/owner.keystore.json --ledger http://ledger:8765 --home /work/home \
      --name Ada --function "e2e contracts assistant" --lease-ttl 120 > /work/init.json
    singular export --home /work/home --move --out /work/ada.capsule >/dev/null
    python -c "import json; from singular import oci; print(json.dumps(oci.push(\"/work/ada.capsule\", \"registry:5000/e2e/ada:v1\")))" > /work/push.json'
AGENT_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["agent_id"])' "$WORK/init.json")"
REF="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["reference"])' "$WORK/push.json")"
echo "agent $AGENT_ID  capsule oci://$REF"

step "host: start the image with a pinned capsule and a secrets file"
printf 'SINGULAR_PASSPHRASE=agent-pass-e2e\nSINGULAR_CAPSULE_PASSPHRASE=capsule-pass-e2e\nOPENROUTER_API_KEY=sk-e2e-not-real\n' > "$WORK/secrets.env"
chmod 644 "$WORK/secrets.env"
start_agent() {
  docker run -d --name "$RUN_ID-agent" --network "$NET" -v "$RUN_ID-home:/agent/home" \
    -v "$WORK/secrets.env:/run/secrets/singular.env:ro" -e SINGULAR_LEDGER=http://ledger:8765 \
    -e SINGULAR_CAPSULE="oci://$REF" -e SINGULAR_REGISTRY_INSECURE=1 -e SINGULAR_ALLOW_INSECURE_LEDGER=1 -e SINGULAR_COMMAND="$COMMAND" "$IMAGE" >/dev/null
}
wait_log() {
  for _ in $(seq 120); do
    docker logs "$RUN_ID-agent" 2>&1 | grep -q "$1" && return 0
    sleep 1
  done
  docker logs "$RUN_ID-agent" 2>&1 | tail -40; return 1
}
start_agent
wait_log "singular-host: running"
docker logs "$RUN_ID-agent" 2>&1 | grep "singular-host: running"
[ "$(lease)" = held ] && echo "ledger: lease held by the container"

sleep "${E2E_SETTLE:-5}"   # let the agent command settle before stopping it
[ -n "${E2E_SHOW_LOGS:-}" ] && docker logs "$RUN_ID-agent" 2>&1 | tail -60
step "docker stop: seal and release"
docker stop -t 60 "$RUN_ID-agent" >/dev/null
docker logs "$RUN_ID-agent" 2>&1 | grep "singular-host: stopped"
[ "$(lease)" = free ] && echo "ledger: lease released"
docker rm "$RUN_ID-agent" >/dev/null

step "restart: the volume already holds the agent"
start_agent
wait_log '"imported": false'
[ "$(lease)" = held ] && echo "ledger: lease held again"
docker stop -t 60 "$RUN_ID-agent" >/dev/null
[ "$(lease)" = free ] && echo "ledger: lease released"
docker rm "$RUN_ID-agent" >/dev/null

step "standalone: bake a second agent into one file with \`singular pack\`"
docker save "$IMAGE" -o "$WORK/runtime.tar"
chmod 644 "$WORK/runtime.tar"
mkdir -p "$WORK/bo" "$WORK/pkg" "$WORK/old" && printf 'You are Bo, a travel planner.\n' > "$WORK/bo/SOUL.md"
docker run --rm --network "$NET" -v "$WORK:/work" --user "$(id -u):$(id -g)" -e HOME=/work "${export_env[@]}" \
  -e SINGULAR_ALLOW_INSECURE_LEDGER=1 --entrypoint sh "$IMAGE" -c '
    set -e
    singular init --owner-key /work/owner.keystore.json --ledger http://ledger:8765 --home /work/bo \
      --name Bo --function "e2e travel planner" --lease-ttl 120 > /work/bo-init.json
    singular export --home /work/bo --move --out /work/bo.capsule >/dev/null
    singular pack /work/bo.capsule --ledger http://ledger:8765 --base /work/runtime.tar --out /work/pkg/bo.tar --tag "'"$RUN_ID"'-bo:v1" > /work/pack.json'
cat "$WORK/pack.json"
rm -f "$WORK/runtime.tar" "$WORK/bo.capsule"
cp "$WORK/pkg/bo.tar" "$WORK/old/bo.tar"
AGENT_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["agent_id"])' "$WORK/bo-init.json")"
docker load -i "$WORK/pkg/bo.tar"
BO_IMAGE="$RUN_ID-bo:v1"
package_no() { in_image python -c "import sys; from singular.ledger.client import HttpLedger
a = HttpLedger('http://ledger:8765').get_agent(sys.argv[1]); print((a.get('package') or {}).get('no', 0))" "$AGENT_ID"; }

step "run it: read-only, no volume, only the folder holding the file and the agent's passphrases"
start_bo() {  # name, folder mounted at /package; the agent can write only its own home and that folder
  docker run -d --name "$1" --network "$NET" --read-only --tmpfs /tmp --user "$(id -u):0" -v "$2:/package" \
    -e SINGULAR_PASSPHRASE=agent-pass-e2e -e SINGULAR_CAPSULE_PASSPHRASE=capsule-pass-e2e \
    -e SINGULAR_ALLOW_INSECURE_LEDGER=1 "$BO_IMAGE" $COMMAND >/dev/null
}
wait_for_exit() { for _ in $(seq 60); do [ "$(docker inspect -f '{{.State.Running}}' "$1")" = false ] && return 0; sleep 1; done; return 1; }
start_bo "$RUN_ID-agent" "$WORK/pkg"
wait_log "singular-host: running"
docker logs "$RUN_ID-agent" 2>&1 | grep "singular-host: running"
[ "$(lease)" = held ] && echo "ledger: Bo's lease held"

step "a second copy started on the same file cannot run while the first lives"
start_bo "$RUN_ID-copy" "$WORK/pkg"
wait_for_exit "$RUN_ID-copy"
docker logs "$RUN_ID-copy" 2>&1 | grep "singular-host: failed"
[ "$(docker inspect -f '{{.State.ExitCode}}' "$RUN_ID-copy")" != 0 ] && echo "copy refused"
[ "$(lease)" = held ] && echo "the first one keeps running"
docker rm -v "$RUN_ID-copy" >/dev/null

step "docker stop: seal, release, rewrite the file, record it on the ledger"
before="$(sha256sum "$WORK/pkg/bo.tar" | cut -c1-64)"
docker stop -t 120 "$RUN_ID-agent" >/dev/null
docker logs "$RUN_ID-agent" 2>&1 | grep "singular-host: packaged"
[ "$(lease)" = free ] && echo "ledger: lease released"
[ "$(sha256sum "$WORK/pkg/bo.tar" | cut -c1-64)" != "$before" ] && echo "the file now holds the new state"
[ "$(package_no)" = 1 ] && echo "ledger: package #1 recorded"
docker rm -v "$RUN_ID-agent" >/dev/null   # the container and its scratch home are gone: only the file is left

step "start again from nothing but the file"
start_bo "$RUN_ID-agent" "$WORK/pkg"
wait_log '"source": "package"'
[ "$(lease)" = held ] && echo "ledger: running again, from the file"
docker stop -t 120 "$RUN_ID-agent" >/dev/null
docker logs "$RUN_ID-agent" 2>&1 | grep -q "singular-host: packaged" && [ "$(package_no)" = 2 ] && echo "ledger: package #2 recorded"
docker rm -v "$RUN_ID-agent" >/dev/null

step "the owner exports and packs the agent again: the new file starts (same state, new digest)"
docker save "$IMAGE" -o "$WORK/runtime.tar"
chmod 644 "$WORK/runtime.tar"
mkdir -p "$WORK/pkg2"
docker run --rm --network "$NET" -v "$WORK:/work" --user "$(id -u):$(id -g)" -e HOME=/work "${export_env[@]}" \
  -e SINGULAR_ALLOW_INSECURE_LEDGER=1 --entrypoint sh "$IMAGE" -c '
    set -e
    singular export --home /work/bo --move --out /work/bo2.capsule >/dev/null
    singular pack /work/bo2.capsule --ledger http://ledger:8765 --base /work/runtime.tar --out /work/pkg2/bo.tar --tag "'"$RUN_ID"'-bo:v2" >/dev/null'
rm -f "$WORK/runtime.tar" "$WORK/bo2.capsule"
docker load -i "$WORK/pkg2/bo.tar" >/dev/null
BO_IMAGE="$RUN_ID-bo:v2" start_bo "$RUN_ID-agent" "$WORK/pkg2"
wait_log '"source": "package"'
[ "$(lease)" = held ] && echo "ledger: the new file runs"
docker stop -t 120 "$RUN_ID-agent" >/dev/null
docker logs "$RUN_ID-agent" 2>&1 | grep -q "singular-host: packaged" && [ "$(package_no)" = 3 ] && echo "ledger: package #3 recorded"
docker rm -v "$RUN_ID-agent" >/dev/null

step "the agent learns something; the old copy of the file is now behind the ledger and refused"
in_image python -c "from pathlib import Path
from singular import agent as A
from singular.ledger.client import HttpLedger
from singular.runtime import SingularGuard
home = A.AgentHome(Path('/work/bo'))
guard = SingularGuard(home, HttpLedger('http://ledger:8765'), 'agent-pass-e2e')
guard.start()
intent = guard.begin_action('memory', {'path': 'memories/MEMORY.md'})
(home.home / 'memories').mkdir(exist_ok=True)
(home.home / 'memories' / 'MEMORY.md').write_text('- the client flies on Fridays\\n')
guard.end_action(intent, 'memory', {'ok': True})
guard.stop()"
start_bo "$RUN_ID-copy" "$WORK/old"
wait_for_exit "$RUN_ID-copy"
docker logs "$RUN_ID-copy" 2>&1 | grep "old copy"
[ "$(lease)" = free ] && echo "old copy refused; nothing runs"

printf '\nPASS: pull, verify, run under the lease, release on stop, restart from the volume; a one-file agent runs alone, rewrites its file on stop, comes back from it, a re-packed file starts, and old copies are refused\n'
