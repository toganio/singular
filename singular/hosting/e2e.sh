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
  docker rmi "$RUN_ID-bo:v1" >/dev/null 2>&1 || true
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

step "standalone: bake a second agent into its own image with \`singular pack\`, as one file"
docker save "$IMAGE" -o "$WORK/runtime.tar"
chmod 644 "$WORK/runtime.tar"
mkdir -p "$WORK/bo" && printf 'You are Bo, a travel planner.\n' > "$WORK/bo/SOUL.md"
docker run --rm --network "$NET" -v "$WORK:/work" --user "$(id -u):$(id -g)" -e HOME=/work "${export_env[@]}" \
  -e SINGULAR_ALLOW_INSECURE_LEDGER=1 --entrypoint sh "$IMAGE" -c '
    set -e
    singular init --owner-key /work/owner.keystore.json --ledger http://ledger:8765 --home /work/bo \
      --name Bo --function "e2e travel planner" --lease-ttl 120 > /work/bo-init.json
    singular export --home /work/bo --move --out /work/bo.capsule >/dev/null
    singular pack /work/bo.capsule --ledger http://ledger:8765 --base /work/runtime.tar --out /work/bo.tar --tag "'"$RUN_ID"'-bo:v1" > /work/pack.json'
cat "$WORK/pack.json"
rm -f "$WORK/runtime.tar"
AGENT_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["agent_id"])' "$WORK/bo-init.json")"
docker load -i "$WORK/bo.tar"
BO_IMAGE="$RUN_ID-bo:v1"

step "run it read-only: only a volume and the agent's passphrases, no capsule source, no ledger setting"
start_bo() {  # name, volume; read-only root filesystem: the agent can write only its own home
  docker run -d --name "$1" --network "$NET" --read-only --tmpfs /tmp -v "$2:/agent/home" -e SINGULAR_PASSPHRASE=agent-pass-e2e \
    -e SINGULAR_CAPSULE_PASSPHRASE=capsule-pass-e2e -e SINGULAR_ALLOW_INSECURE_LEDGER=1 "$BO_IMAGE" $COMMAND >/dev/null
}
start_bo "$RUN_ID-agent" "$RUN_ID-home-bo"
wait_log "singular-host: running"
docker logs "$RUN_ID-agent" 2>&1 | grep "singular-host: running"
[ "$(lease)" = held ] && echo "ledger: Bo's lease held by its own image"

step "a copy of the same image on a second volume cannot run while the first lives"
start_bo "$RUN_ID-copy" "$RUN_ID-home-copy"
for _ in $(seq 60); do [ "$(docker inspect -f '{{.State.Running}}' "$RUN_ID-copy")" = false ] && break; sleep 1; done
docker logs "$RUN_ID-copy" 2>&1 | grep "singular-host: failed"
[ "$(docker inspect -f '{{.State.ExitCode}}' "$RUN_ID-copy")" != 0 ] && echo "copy refused"
docker logs "$RUN_ID-agent" 2>&1 | grep -q "singular-host: running" && [ "$(lease)" = held ] && echo "the first one keeps running"
docker stop -t 60 "$RUN_ID-agent" >/dev/null
[ "$(lease)" = free ] && echo "ledger: lease released"

printf '\nPASS: pull, verify, run under the lease, release on stop, restart from the volume; a packed image runs alone and its copies cannot run beside it\n'
