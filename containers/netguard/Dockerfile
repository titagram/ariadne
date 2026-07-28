# syntax=docker/dockerfile:1
# Ariadne netguard — minimal pinned firewall image.

ARG NETGUARD_BASE_REF

FROM alpine@${NETGUARD_BASE_REF}

RUN apk add --no-cache nftables
