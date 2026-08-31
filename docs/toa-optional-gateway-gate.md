# Optional TOA verify before gateway enable

Unla turns existing MCP servers and APIs into MCP endpoints via configuration,
with hot-reload and a management UI. That answers proxying and registration.
It does not prove that a tool recently delivered a real result under an outside
probe.

[TOA](https://github.com/Carmel-Labs-Inc/toa) (`toa/0.1`) is an Apache-2.0 signed
JSON evidence format for MCP tool delivery (reach, invoke, functional, shape,
and related layers). It is not a wire protocol. It is not meant to run on every
live `tools/call`.

## Suggested fit

Optional, off by default. Before enabling or promoting a proxied MCP upstream
(or publishing a new config version), require an attestation and verify it offline with a pinned emitter
(`--require-emitter`) and optional freshness (`--max-age`).

- Any party can emit if they sign the schema.
- AgentStatus is one optional emitter.
- No AgentStatus account is required to verify.

```yaml
      # After your Unla config lint / smoke checks.
      - name: Verify tool delivery attestation
        if: hashFiles('toa.json') != ''
        run: |
          pip install "git+https://github.com/Carmel-Labs-Inc/toa.git@5a1bf1cf6a15a4864ea809fe7b2a073f2cef4e22#subdirectory=python"
          toa-verify toa.json --require-emitter agentstatus --require-layer functional=pass --max-age 7d
```

Copy-paste workflow: [`examples/toa-after-gateway.yml`](../examples/toa-after-gateway.yml).

## Out of scope

- Replacing Unla OAuth, multi-tenant config, or the proxy hot path
- Signing every production `tools/call`
- Changing gateway runtime code

Product docs: https://docs.unla.amoylab.com
