#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

install_go_dependencies

# install docker

# DOCKER_VERSION="25.0"

# curl -fsSL https://get.docker.com -o get-docker.sh
# sudo sh ./get-docker.sh --version $DOCKER_VERSION

# Debug info for zswap test environment - TODO: remove after stabilization
set -x
uname -a
cat /proc/meminfo
cat /sys/module/zswap/parameters/enabled 2>/dev/null || echo "zswap module not loaded"
sudo grep -r . /sys/kernel/debug/zswap/ 2>/dev/null || echo "debugfs zswap not accessible"
mount
head -1 /sys/fs/cgroup/memory.stat 2>/dev/null && grep -i zswp /sys/fs/cgroup/memory.stat 2>/dev/null || echo "cgroup v2 not available or no zswap fields"
cat /proc/config.gz | gunzip | grep -i swap
set +x

go test -timeout 20m -v ./tests
