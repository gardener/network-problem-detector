# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# builder
FROM golang:1.24.5 AS builder

WORKDIR /build

# Copy go mod and sum files
COPY go.mod go.sum ./
# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

COPY . .
ARG TARGETARCH
RUN make release GOARCH=$TARGETARCH

############# network-problem-detector
FROM gcr.io/distroless/static-debian12 AS network-problem-detector

COPY --from=builder /build/nwpdcli /nwpdcli
ENTRYPOINT ["/nwpdcli"]
