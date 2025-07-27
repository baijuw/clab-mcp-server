# ContainerLab MCP Server

This MCP (Model Context Protocol) server provides tools for interacting with ContainerLab Linux containers via Docker. It enables network configuration, connectivity testing, and routing management for network lab environments.

## Docker Build

### Standard Build
```bash
docker build . -t clab-mcp-server
```

### Build with Proxy (if behind corporate proxy)
```bash
docker build . --build-arg HTTP_PROXY=<proxy server> --build-arg HTTPS_PROXY=<proxy server> --build-arg NO_PROXY=<subnets to skip> -t clab-mcp-server
```

## Docker Run

Run the ContainerLab MCP server in a container:

```bash
docker run -d -p 8989:8989 clab-mcp-server
```

**Port 8989** is used because the MCP server inside the container listens on port 8989. The port mapping `-p 8989:8989` makes the server accessible from the host.

## Available Tools

- **get_clab_linux_nodes** - Discover and inventory all ContainerLab Linux nodes with their network interface details
- **set_ip** - Configure network connectivity by creating VLAN interfaces and assigning IP addresses  
- **delete_vlan_interface** - Remove VLAN interfaces and clean up network configuration
- **test_connectivity** - Verify network connectivity between containers using ping
- **add_static_route** - Add static routes to container routing tables for L3 domain testing
