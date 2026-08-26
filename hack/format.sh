#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

set -e

echo "> Format"

${GOIMPORTS:-goimports} -l -w $@
