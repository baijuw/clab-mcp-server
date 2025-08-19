# ContainerLab MCP Server

This MCP (Model Context Protocol) server provides tools for interacting with ContainerLab Linux containers acting as network clients. It enables network configuration, connectivity testing, and routing management for network clients in the lab environments. 
This MCP server is limited to discovering and automating tasks on clab nodes of type Linux.

## Docker Build

### Standard Build
```bash
docker build . -t clab-mcp-server
```

### Build with Proxy (if behind corporate proxy)
```bash
docker build . --build-arg HTTP_PROXY=<proxy server> --build-arg HTTPS_PROXY=<proxy server> --build-arg NO_PROXY=<subnets to skip> -t clab-mcp-server
```

## Configuration

### Docker Host Configuration

The MCP server needs to connect to a Docker daemon to manage ContainerLab containers. You can configure the Docker host IP address in several ways:

1. **Environment Variable** (recommended for Docker runs):
   ```bash
   export DOCKER_HOST_IP=your.docker.host.ip
   ```

2. **Command Line Argument** (for direct Python execution):
   ```bash
   python clab_mcp_server.py --docker-host-ip your.docker.host.ip
   ```

3. **Default Behavior**: If neither is specified, it defaults to `localhost`

### Available Command Line Options

```bash
python clab_mcp_server.py --help
```

- `--docker-host-ip`: Docker host IP address (default: localhost, or set DOCKER_HOST_IP env var)
- `--docker-port`: Docker daemon port (default: 2375)
- `--docker-tls`: Use TLS for Docker connection (default: False)
- `--mcp-host`: MCP server host (default: 0.0.0.0)
- `--mcp-port`: MCP server port (default: 8989)

## Docker Run

**Important:** This MCP server connects to the CLAB server using Docker TCP transport. The CLAB Docker service must be enabled to be managed by Docker TCP-based commands.

### Basic Run (Docker host on localhost)
```bash
docker run -d -p 8989:8989 clab-mcp-server
```

### Run with Custom Docker Host IP
```bash
docker run -d --name clab-mcp-server -p 8989:8989 -e DOCKER_HOST_IP=<docker-host-ip> clab-mcp-server
```

### Run with Multiple Environment Variables
```bash
docker run -d -p 8989:8989 \
  -e DOCKER_HOST_IP=<docker-host-ip> \
  -e DOCKER_PORT=2375 \
  --name clab-mcp-server \
  clab-mcp-server
```

**Port 8989** is used because the MCP server inside the container listens on port 8989. The port mapping `-p 8989:8989` makes the server accessible from the host.

## Available Tools

- **get_clab_linux_nodes** - Discover and inventory all ContainerLab Linux nodes with their network interface details
- **set_ip** - Configure network connectivity by creating VLAN interfaces and assigning IP addresses  
- **delete_vlan_interface** - Remove VLAN interfaces and clean up network configuration
- **test_connectivity** - Verify network connectivity between containers using ping
- **add_static_route** - Add static routes to container routing tables for L3 domain testing
