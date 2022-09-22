#!/bin/sh

set -e

build_assets() {
  yarn install --pure-lockfile --production
  flask assets build
}

action=$1
shift 1

case "$action" in
dev)
  build_assets
  flask db upgrade
  exec flask run --host 0.0.0.0
  ;;
*)
  exec "$action" "$@"
  ;;
esac
