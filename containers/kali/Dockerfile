# syntax=docker/dockerfile:1
# Ariadne Kali Linux container — pinned base, curated tools, unprivileged user.

ARG KALI_BASE_REF

FROM kalilinux/kali-rolling@${KALI_BASE_REF}

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install curated tool manifest packages
COPY tool-manifest.yaml /tmp/tool-manifest.yaml
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        $(grep -v '^#' /tmp/tool-manifest.yaml | sed -n 's/^  - //p') && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/tool-manifest.yaml

# Create unprivileged runtime user
RUN useradd -m -s /bin/bash ariadne && \
    chmod 755 /home/ariadne

# Evidence and engagement mount points
RUN mkdir -p /evidence /engagement && \
    chown ariadne:ariadne /evidence /engagement

USER ariadne
WORKDIR /home/ariadne

# Default command: interactive shell
CMD ["/bin/bash"]
