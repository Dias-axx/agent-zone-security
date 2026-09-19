# Egress gateway image: mitmproxy + this repo's own policy engine, so egress
# enforcement at the proxy is the same code as everywhere else, not a second
# reimplementation of the allowlist logic. See policy_addon.py's docstring and
# docs/adr/0002-tls-terminating-egress-gateway.md.
#
# Build from the repo root:
#   docker build -f deploy/mitmproxy/Dockerfile -t <your-registry>/agent-zone-control-egress-gateway:latest .
FROM mitmproxy/mitmproxy:12.2

# PyYAML is not bundled in the mitmproxy base image (verified by building this
# image and running it — see the commit that added this line for the actual
# ModuleNotFoundError it fixes). control/policy_engine.py and
# detection/normalise.py are pure stdlib, no other install needed.
RUN pip3 install --no-cache-dir pyyaml>=6.0

COPY control/policy_engine.py /app/control/policy_engine.py
COPY control/__init__.py /app/control/__init__.py
COPY detection/normalise.py /app/detection/normalise.py
COPY detection/__init__.py /app/detection/__init__.py
COPY registry/agents.yaml /app/registry/agents.yaml
COPY policy/examples/ /app/policy/examples/
COPY deploy/mitmproxy/policy_addon.py /app/policy_addon.py

EXPOSE 8080

ENTRYPOINT ["mitmdump"]
CMD ["--mode", "regular", "--listen-port", "8080", "--set", "confdir=/home/mitmproxy/.mitmproxy", "-s", "/app/policy_addon.py"]
