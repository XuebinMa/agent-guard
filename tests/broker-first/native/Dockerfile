# CI supplies a reviewed digest-pinned Ubuntu base. No default mutable tag.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# No credential, broker, host configuration, or implicit volume in this image.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 git gcc libc6-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY agent_fixture.py /opt/agent/fixture.py
RUN chmod 0555 /opt/agent/fixture.py

# launch.py supplies the fixed identity, environment, entrypoint and arguments.
