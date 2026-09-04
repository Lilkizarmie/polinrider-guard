#!/usr/bin/env bash
# Null-route the hosts this malware family uses to resolve its C2 server.
#
# It reads an attacker Ethereum wallet's latest transaction (via these public
# RPC / block-explorer endpoints) and decodes the C2 IP from it. Break that
# lookup and the payload can't find its server — stage 2 never starts.
#
# Safe for a mobile-app dev machine: none of these are needed unless you do
# Ethereum work. If you ever do, comment the relevant line out.
#
# Run:  sudo bash block-c2-hosts.sh          (add block)
#       sudo bash block-c2-hosts.sh --undo   (remove block)
set -euo pipefail

MARK_BEGIN="# >>> malware-guard C2 block >>>"
MARK_END="# <<< malware-guard C2 block <<<"
HOSTS=/etc/hosts

BLOCKED=(
  ethereum-rpc.publicnode.com
  ethereum.publicnode.com
  eth.drpc.org
  eth.blockscout.com
  blockscout.com
  1rpc.io
  eth-mainnet.blastapi.io
  eth-mainnet.public.blastapi.io
  public.blastapi.io
  api.etherscan.io
  etherscan.io
  rpc.ankr.com
  eth.llamarpc.com
  cloudflare-eth.com
  mainnet.infura.io
)

if [ "$(id -u)" -ne 0 ]; then echo "run with sudo"; exit 1; fi

# Always strip any previous block first (idempotent).
sed -i '' "/$MARK_BEGIN/,/$MARK_END/d" "$HOSTS"

if [ "${1:-}" = "--undo" ]; then
  echo "C2 host block removed."
  dscacheutil -flushcache 2>/dev/null || true
  killall -HUP mDNSResponder 2>/dev/null || true
  exit 0
fi

{
  echo "$MARK_BEGIN"
  for h in "${BLOCKED[@]}"; do
    echo "0.0.0.0 $h"
    echo "::1 $h"
  done
  echo "$MARK_END"
} >> "$HOSTS"

dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true
echo "Blocked ${#BLOCKED[@]} C2-resolution hosts in $HOSTS."
