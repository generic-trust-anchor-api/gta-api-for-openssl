#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1

set -euo pipefail

export _WD="${WORK_DIR:-.}"
echo "Working directory: $_WD"
readonly DOCKER_COMPOSE_FILE="./ejbca/docker-compose.yml"

function ejbca_is_operational
{
    wget -q --spider --timeout=2 --tries=1 http://localhost:6080/ejbca/ra/cas.xhtml
}

function wait_for_ejbca
{
    echo "Waiting for EJBCA to become operational..."

    for _ in {1..60}; do
        if ejbca_is_operational; then
            echo "EJBCA is operational"
            return "$EXIT_SUCCESS"
        fi

        sleep 5
    done

    echo "EJBCA did not become operational in time" >&2
    return "$EXIT_FAILURE"
}

function ensure_ejbca_operational
{
    if ejbca_is_operational; then
        echo "EJBCA is already operational"
        return "$EXIT_SUCCESS"
    fi

    echo "Starting EJBCA demo stack"
    docker compose -f "$DOCKER_COMPOSE_FILE" up -d

    wait_for_ejbca
}

export GTA_API_STATE_DIR="$_WD/tmp/gta_api_state"
export GTA_STATE_DIRECTORY="$GTA_API_STATE_DIR"
export DEMO_CREDENTIAL_DIR="$_WD/tmp/cmp_example"

if [[ -d "$GTA_STATE_DIRECTORY" ]]; then
    echo "$GTA_STATE_DIRECTORY directory exists."
else
    echo "Create $GTA_STATE_DIRECTORY directory."
    mkdir -p "$GTA_STATE_DIRECTORY"
fi

if [[ -d "$DEMO_CREDENTIAL_DIR" ]]; then
    echo "$DEMO_CREDENTIAL_DIR directory exists."
else
    echo "Create $DEMO_CREDENTIAL_DIR directory."
    mkdir -p "$DEMO_CREDENTIAL_DIR"
fi

rm -f "$GTA_STATE_DIRECTORY/"*
rm -f "$DEMO_CREDENTIAL_DIR/"*

if openssl list -provider gta -providers; then
    echo "The gta provider installed... OK"
else
    echo "Missing gta provider"
    exit "$EXIT_FAILURE"
fi

if gta-cli personality_attributes_enumerate --pers=test >/dev/null; then
    echo "The gta-cli installed... OK"
else
    echo "Missing gta-cli"
    exit "$EXIT_FAILURE"
fi

if docker --version >/dev/null 2>&1; then
    echo "docker installed... OK"
else
    echo "Missing docker" >&2
    return "$EXIT_FAILURE"
fi

if docker compose version >/dev/null 2>&1; then
    echo "docker compose supported... OK"
else
    echo "Missing docker compose" >&2
    return "$EXIT_FAILURE"
fi

ensure_ejbca_operational

exit "$EXIT_SUCCESS"