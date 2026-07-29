# syntax=docker/dockerfile:1
# Ariadne Kali Linux container — pinned base, curated tools, unprivileged user.

ARG KALI_BASE_REF

FROM kalilinux/kali-rolling@${KALI_BASE_REF}

ARG NUCLEI_TEMPLATES_REF

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
