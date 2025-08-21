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

### Network Discovery
- **get_clab_linux_nodes** - Discover and inventory all ContainerLab Linux nodes with their network interface details

### Interface Configuration  
- **set_ip** - Configure network connectivity by creating VLAN interfaces and assigning IP addresses
- **delete_vlan_interface** - Remove VLAN interfaces and clean up network configuration

### Bond Interface Management
- **create_bond_interface** - Create bond interfaces for network redundancy and load balancing
- **delete_bond_interface** - Delete bond interfaces and restore slave interfaces to their original state

### Interface Inspection & Troubleshooting
- **get_interface_info** - Retrieve comprehensive configuration and status information for network interfaces (supports physical, VLAN, and bond interfaces)
- **test_connectivity** - Verify network connectivity between containers using ping

### Routing Configuration
- **add_static_route** - Add static routes to container routing tables for L3 domain testing
- **check_routes** - Retrieve and analyze container routing tables for troubleshooting
- **route_delete** - Remove static routes from container routing tables

## Tool Details

### Network Discovery Tools

#### `get_clab_linux_nodes`
Discovers all running ContainerLab containers with the `clab-node-kind` label set to "linux" and retrieves detailed network interface information including IP addresses, MAC addresses, and interface states.

**Use Cases:**
- Network topology discovery
- Interface configuration verification  
- MAC address learning
- Connectivity troubleshooting

### Interface Configuration Tools

#### `set_ip`
Creates VLAN interfaces and assigns IP addresses with optional gateway configuration.

**Parameters:**
- `container_name`: Target container name
- `interface_name`: Base interface name (e.g., 'eth1')
- `ip_with_mask`: IP address with CIDR notation (e.g., '192.168.1.10/24')
- `vlan_id`: VLAN ID number (1-4094)
- `gateway_ip`: Optional default gateway IP address

**Operations:**
1. Creates VLAN interface (e.g., eth1.100 for VLAN 100)
2. Brings the interface up
3. Assigns IP address
4. Optionally configures default gateway

#### `delete_vlan_interface`
Removes VLAN interfaces and cleans up associated configuration.

**Parameters:**
- `container_name`: Target container name
- `interface_name`: Base interface name
- `vlan_id`: VLAN ID to delete

### Bond Interface Management Tools

#### `create_bond_interface`
Creates bonded network interfaces for redundancy and load balancing.

**Parameters:**
- `container_name`: Target container name
- `bond_name`: Bond interface name (e.g., 'bond0')
- `slave_interfaces`: List of interfaces to bond (e.g., ['eth1', 'eth2'])
- `bond_mode`: Bonding mode (default: 'active-backup')
- `miimon`: MII monitoring interval in milliseconds (default: 100)

**Supported Bond Modes:**
- `active-backup`: One interface active, others standby
- `balance-rr`: Round-robin load balancing
- `balance-xor`: XOR hash load balancing
- `broadcast`: Transmit on all interfaces
- `802.3ad`: IEEE 802.3ad dynamic link aggregation (LACP)
- `balance-tlb`: Adaptive transmit load balancing
- `balance-alb`: Adaptive load balancing

#### `delete_bond_interface`
Removes bond interfaces and restores slave interfaces to independent operation.

**Parameters:**
- `container_name`: Target container name
- `bond_name`: Bond interface name to delete
- `slave_interfaces`: List of slave interfaces to restore

**Operations:**
1. Brings down bond interface
2. Removes slave interfaces from bond
3. Deletes bond interface
4. Restores slave interfaces as independent interfaces

### Interface Inspection & Troubleshooting Tools

#### `get_interface_info`
Provides comprehensive inspection of network interfaces with specialized support for different interface types.

**Parameters:**
- `container_name`: Target container name
- `interface_name`: Interface to analyze (e.g., 'eth1', 'bond0', 'eth1.100')

**Returns detailed information about:**
- **Basic Properties:** State (up/down), MAC address, MTU
- **IP Configuration:** All assigned IP addresses with CIDR notation
- **Bond Details** (for bond interfaces):
  - Bond mode and configuration parameters
  - Slave interface status and active/backup states  
  - MII monitoring status and link state
  - Currently active slave identification
- **VLAN Details** (for VLAN interfaces):
  - VLAN ID and parent interface
  - VLAN-specific configuration
- **Statistics:** RX/TX packets, bytes, errors, dropped packets

**Use Cases:**
- Post-configuration verification after `set_ip` or `create_bond_interface`
- Network troubleshooting and diagnostics
- Bond interface health monitoring
- Interface performance analysis

#### `test_connectivity`
Tests network reachability between containers using ICMP ping.

**Parameters:**
- `container_name`: Source container name
- `destination_ip`: Target IP address to test

**Features:**
- Sends 3 ping packets with 2-second timeout
- Provides detailed connectivity diagnostics
- Includes troubleshooting guidance for common failure scenarios

### Routing Configuration Tools

#### `add_static_route`
Adds static routes to container routing tables for custom network topologies.

**Parameters:**
- `container_name`: Target container name
- `destination_network`: Target network in CIDR notation
- `gateway_ip`: Next-hop gateway IP address  
- `interface_name`: Interface to use for the route

**Use Cases:**
- L3 domain testing in ContainerLab
- Custom routing policies
- Multi-homed network configurations
- Network segmentation and isolation

#### `check_routes`
Retrieves and analyzes the routing table from a container for network troubleshooting.

**Parameters:**
- `container_name`: Target container name
- `destination_filter`: Optional filter for specific destinations (e.g., 'default', '192.168.10.0/24')

**Returns:**
- **Structured Route Data:** Parsed route entries with destination, gateway, interface, metric, protocol, and scope
- **Raw Output:** Complete `ip route show` command output
- **Route Statistics:** Total number of routes found
- **Filter Information:** Applied destination filter details

**Use Cases:**
- **Inter-VLAN Testing:** Verify routing between different VLANs and subnets
- **Route Validation:** Confirm static routes added with `add_static_route`
- **Connectivity Troubleshooting:** Understand traffic flow paths in complex topologies
- **Network Diagnostics:** Debug routing problems and validate configurations
- **Topology Analysis:** Analyze routing paths for network optimization
- **Gateway Verification:** Confirm default gateway and specific route configurations

#### `route_delete`
Removes static routes from a container's routing table for cleanup and reconfiguration.

**Parameters:**
- `container_name`: Target container name
- `destination_network`: Target network in CIDR notation to remove routes for
- `gateway_ip`: Optional gateway IP to match for route deletion (if not specified, matches any gateway)
- `interface_name`: Optional interface name to match for route deletion (if not specified, matches any interface)

**Flexible Deletion Options:**
- **Destination Only:** Remove all routes to a specific destination (`route_delete("container1", "192.168.10.0/24")`)
- **Destination + Gateway:** Remove route via specific gateway (`route_delete("container1", "192.168.10.0/24", "10.0.0.1")`)
- **Destination + Interface:** Remove route via specific interface (`route_delete("container1", "192.168.10.0/24", None, "eth1.100")`)
- **Complete Specification:** Remove exact route match (`route_delete("container1", "192.168.10.0/24", "10.0.0.1", "eth1.100")`)

**Use Cases:**
- **Route Cleanup:** Remove obsolete or incorrect static routes after testing
- **Configuration Changes:** Remove old routes before adding new ones for reconfiguration
- **Troubleshooting:** Remove conflicting routes that are causing connectivity problems
- **Network Reset:** Restore default routing behavior by removing custom routes
- **Lab Management:** Clean up routing tables between different test scenarios
- **Error Recovery:** Remove routes that were added incorrectly or are causing issues

## Security Features

- **eth0 Protection:** All interface modification tools prevent accidental changes to eth0 (management interface)
- **Input Validation:** Comprehensive parameter validation and error handling
- **Safe Operations:** Graceful handling of missing interfaces and existing configurations
