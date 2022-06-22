# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# builder
FROM golang:1.18.3 AS builder

WORKDIR /build
COPY . .
RUN make release

############# network-problem-detector
FROM gcr.io/distroless/static-debian11 AS network-problem-detector

COPY --from=builder /build/nwpdcli /nwpdcli
ENTRYPOINT ["/nwpdcli"]
