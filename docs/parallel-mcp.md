# Public web search through Parallel MCP

Use Unla's existing MCP proxy to make Parallel available to your MCP clients at
one gateway endpoint. This example uses the remote server directly; it does not
need a local MCP server process or a Parallel API key. Keyless access is rate
limited. See [Parallel MCP setup](https://docs.parallel.ai/integrations/mcp/quickstart)
for the available tools and current limits.

## Add the gateway configuration

1. Start Unla using the [quick start](../README.md#-getting-started).
2. In the web interface, click **Add MCP Server**, paste
   [configs/proxy-parallel.yaml](../configs/proxy-parallel.yaml), and save.
   For another tenant, set `tenant` to its name and place `routers[0].prefix`
   under that tenant's configured prefix. For example, tenant `team` with
   prefix `/team` can use `/team/parallel`.
3. Connect your MCP client to
   `http://localhost:5235/gateway/parallel/mcp` using Streamable HTTP.
   For a remote deployment, replace the host and port with your gateway address
   and retain your deployment's access controls.
   If you changed the router prefix, use that prefix in the client URL too;
   the example above becomes `http://localhost:5235/team/parallel/mcp`.

The `routers.server` and `mcpServers.name` values match so Unla treats the backend
as an MCP server. Do not put this backend in `servers`, which is for HTTP API
tools. `policy: "onDemand"` and `preinstalled: false` avoid opening the backend
while the gateway builds its routes. The API server can still connect for
background MCP metadata refresh; that discovery does not run a web search.
Search runs when a client calls `web_search`. Existing configurations continue
to work alongside this example.

## Use it in an agent run

Enable the gateway's `web_search` tool in your MCP client, keeping its usual tool
approval settings. For example, ask:

> Use web_search to find the official Go 1.25 release notes. Summarize one change
> and cite the original source URL returned by the tool.

An agent can call the discovered tool with:

```json
{
  "objective": "Find the official Go 1.25 release notes and one documented change.",
  "search_queries": ["site:go.dev Go 1.25 release notes"]
}
```

Use only public queries that you authorize to be sent to Parallel. Keep private
inputs and credentials out of search arguments. Unla discovers the upstream MCP
tools and forwards calls and text results through its existing proxy; source
URLs in the returned text are available to the agent for citations.

Check the tool result for an original source URL, then check that the agent's
answer cites that URL. If search returns no sources, ask the agent to say so.
If the upstream is unavailable or rate limited, inspect the tool error and
retry later; do not treat a failed call as evidence. Tools that require
authentication are outside this keyless example.

To disable this integration, remove its configuration and disable the endpoint
in your MCP client.
