# syntax=docker/dockerfile:1
# Ariadne Kali Linux container — pinned base, curated tools, unprivileged user.

ARG KALI_BASE_REF

FROM kalilinux/kali-rolling@${KALI_BASE_REF}

ARG NUCLEI_TEMPLATES_REF
ARG TARGETARCH
ARG KATANA_VERSION=1.6.1
ARG KATANA_AMD64_SHA256=503754f1bd370c3ef287df6998e317baed2dd75bdd13ea64034f09b80ca393f3
ARG KATANA_ARM64_SHA256=663b4ed2c6559a7dacc819e816889940d567ff554ac3f543c8c8f9b50245cd45

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Build Ariadne's minimal specialist toolchain from official Kali packages.
# Deliberately do not install kali-linux-headless or another bulk metapackage.
COPY tool-manifest.yaml /tmp/tool-manifest.yaml
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        $(sed -n '/^packages:/,/^[^ ]/s/^  - //p' /tmp/tool-manifest.yaml) && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/tool-manifest.yaml

# ProjectDiscovery does not publish Katana through Kali rolling. Install its
# official release asset only after architecture-specific SHA-256 validation.
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) KATANA_SHA256="${KATANA_AMD64_SHA256}" ;; \
        arm64) KATANA_SHA256="${KATANA_ARM64_SHA256}" ;; \
        *) echo "Unsupported Katana architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    KATANA_ARCHIVE="/tmp/katana_${KATANA_VERSION}_linux_${TARGETARCH}.zip"; \
    curl -fsSL \
        "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${TARGETARCH}.zip" \
        -o "${KATANA_ARCHIVE}"; \
    echo "${KATANA_SHA256}  ${KATANA_ARCHIVE}" | sha256sum -c -; \
    mkdir /tmp/katana-release; \
    python3 -m zipfile -e "${KATANA_ARCHIVE}" /tmp/katana-release; \
    install -m 0755 /tmp/katana-release/katana /usr/local/bin/katana; \
    rm -rf "${KATANA_ARCHIVE}" /tmp/katana-release

# Install the curated official Nuclei catalog at the same immutable revision
# used by Ariadne's local selector index.
RUN test -n "${NUCLEI_TEMPLATES_REF}" && \
    git clone --filter=blob:none --no-checkout \
        https://github.com/projectdiscovery/nuclei-templates \
        /opt/nuclei-templates && \
    git -C /opt/nuclei-templates fetch --depth 1 origin \
        "${NUCLEI_TEMPLATES_REF}" && \
    git -C /opt/nuclei-templates checkout --detach FETCH_HEAD && \
    test "$(git -C /opt/nuclei-templates rev-parse HEAD)" = \
        "${NUCLEI_TEMPLATES_REF}"

# Create unprivileged runtime user
RUN useradd -m -s /bin/bash ariadne && \
    chmod 755 /home/ariadne

# Evidence and engagement mount points
RUN mkdir -p /evidence /engagement && \
    chown -R ariadne:ariadne /evidence /engagement /opt/nuclei-templates

USER ariadne
WORKDIR /home/ariadne

# Default command: interactive shell
CMD ["/bin/bash"]
