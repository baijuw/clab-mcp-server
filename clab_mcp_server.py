#!/usr/bin/env python3
"""
FastMCP 2.0 ContainerLab Server
Provides MCP tools for interacting with ContainerLab containers via Docker.
"""

import docker
from typing import List, Dict, Optional
import logging
import json
import subprocess
import sys
from fastmcp import FastMCP

logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("ContainerLab MCP Server 🚀")

class ContainerLabClient:
    """
    A client class for interacting with ContainerLab containers on a remote Docker host.
    Stores the docker_host_ip once and provides methods for various operations.
    """
    
    def __init__(self, docker_host_ip: str, port: int = 2376, tls: bool = False, 
                 cert_path: Optional[str] = None, key_path: Optional[str] = None, 
                 ca_cert_path: Optional[str] = None):
        """
        Initialize the ContainerLabClient.
        
        Args:
            docker_host_ip: IP address of the Docker host
            port: Docker daemon port (default: 2376 for TLS, 2375 for non-TLS)
            tls: Whether to use TLS connection
            cert_path: Path to client certificate file
            key_path: Path to client key file
            ca_cert_path: Path to CA certificate file
        """
        self.docker_host_ip = docker_host_ip
        self.port = port
        self.tls = tls
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path

# Global client instance - will be initialized when server starts
clab_client: Optional[ContainerLabClient] = None

def initialize_client(docker_host_ip: str = "10.58.65.16", port: int = 2375, tls: bool = False):
    """Initialize the global ContainerLabClient instance."""
    global clab_client
    clab_client = ContainerLabClient(docker_host_ip, port, tls)

@mcp.tool
def get_clab_linux_nodes() -> List[Dict]:
    """
    Discover and inventory all ContainerLab Linux nodes with their network interface details.
    
    This tool connects to the configured Docker host, identifies all running ContainerLab containers 
    that have the 'clab-node-kind' label set to 'linux', and retrieves detailed network interface 
    information from each. Use this tool when you need to:
    - Get an overview of all available ContainerLab Linux nodes
    - Understand the current network topology and interface configurations
    - Identify which containers are available for network operations
    - Troubleshoot network connectivity issues by examining interface states
    - To learn and verify MAC address 
    
    The tool returns comprehensive IP address information including interface names, IP addresses,
    MAC addresses, and interface states for all network interfaces in each container.
    
    Returns:
        List of dictionaries with format [{container_name: ip_command_output}, ...]
        where ip_command_output is the parsed JSON from 'ip -j address show' containing
        detailed interface information including IP addresses, MAC addresses, and interface states
        
    Raises:
        docker.errors.DockerException: If connection to Docker host fails
        ConnectionError: If unable to connect to specified host/port
    """
    try:
        if clab_client is None:
            raise RuntimeError("ContainerLab client not initialized. Call initialize_client() first.")
        
        if clab_client.tls:
            if clab_client.cert_path and clab_client.key_path:
                tls_config = docker.tls.TLSConfig(
                    client_cert=(clab_client.cert_path, clab_client.key_path),
                    ca_cert=clab_client.ca_cert_path,
                    verify=True
                )
            else:
                tls_config = docker.tls.TLSConfig(
                    ca_cert=clab_client.ca_cert_path,
                    verify=True
                )
            base_url = f"https://{clab_client.docker_host_ip}:{clab_client.port}"
        else:
            tls_config = None
            base_url = f"tcp://{clab_client.docker_host_ip}:{clab_client.port}"

        # Connect to Docker daemon
        client = docker.DockerClient(base_url=base_url, tls=tls_config)
        
        # Get all running containers
        containers = client.containers.list(all=False)
        
        # Filter for Linux clab containers using labels
        results = []
        for container in containers:
            # Inspect container to get detailed information including labels
            container_details = client.api.inspect_container(container.id)
            
            # Check if the container has the clab-node-kind label set to "linux"
            labels = container_details.get('Config', {}).get('Labels', {})
            clab_node_kind = labels.get('clab-node-kind')
            
            if clab_node_kind and clab_node_kind.lower() == "linux":
                try:
                    # Execute 'ip -j address show' command in the container
                    exec_result = client.api.exec_create(
                        container.id,
                        'ip -j address show',
                        stdout=True,
                        stderr=True
                    )
                    
                    output = client.api.exec_start(exec_result['Id'])
                    output_str = output.decode('utf-8').strip()
                    
                    # Parse JSON output
                    try:
                        ip_info = json.loads(output_str)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON output for container {container.name}: {e}")
                        ip_info = {"error": f"Failed to parse JSON: {output_str}"}
                    
                    # Create entry with container name as key
                    results.append({container.name: ip_info})
                    logger.info(f"Successfully executed ip command in container {container.name}")
                    
                except Exception as e:
                    logger.error(f"Failed to execute command in container {container.name}: {e}")
                    results.append({container.name: {"error": str(e)}})
        
        logger.info(f"Found {len(results)} Linux clab nodes on remote host")
        return results
        
    except Exception as e:
        logger.error(f"Error connecting to Docker host: {e}")
        raise
    finally:
        if 'client' in locals():
            client.close()

@mcp.tool
def set_ip(
    container_name: str,
    interface_name: str,
    ip_with_mask: str,
    vlan_id: int,
    gateway_ip: Optional[str] = None
) -> Dict:
    """
    Configure network connectivity by creating a VLAN interface and assigning an IP address.
    
    This tool performs comprehensive network configuration on a ContainerLab container by:
    1. Creating a new VLAN interface (e.g., eth1.100 for VLAN 100)
    2. Bringing the interface up and making it active
    3. Assigning the specified IP address with subnet mask
    4. Optionally configuring a default gateway for routing
    
    Use this tool when you need to:
    - Set up network connectivity between containers in different VLANs
    - Configure IP addresses for network testing and simulation
    - Establish communication paths in network lab environments
    - Create isolated network segments for security testing
    
    This is typically the first step in setting up network communication between 
    ContainerLab nodes. The tool handles all the underlying Linux networking commands
    and provides detailed feedback on each configuration step.
    
    Args:
        container_name: Name of the ContainerLab container to configure
        interface_name: Base interface name (e.g., 'eth1') - the VLAN interface will be created as interface_name.vlan_id
        ip_with_mask: IP address with CIDR notation (e.g., '192.168.1.10/24', '10.0.0.1/16')
        vlan_id: VLAN ID number (1-4094) to create the tagged interface
        gateway_ip: Optional default gateway IP address for routing to other networks
    
    Returns:
        Dictionary containing:
        - status: 'success' or 'error'
        - messages: List of operation steps performed
        - container, interface, ip, vlan_id, gateway: Configuration details
        - error: Error message if operation failed
        
    Raises:
        docker.errors.DockerException: If container is not found or not accessible
        ValueError: If IP address format is invalid or VLAN ID is out of range
    """
    result = {
        "status": "success",
        "container": container_name,
        "interface": interface_name,
        "ip": ip_with_mask,
        "vlan_id": vlan_id,
        "gateway": gateway_ip,
        "messages": []
    }
    
    try:
        if clab_client is None:
            raise RuntimeError("ContainerLab client not initialized. Call initialize_client() first.")
        
        # Protection: Prevent any actions on eth0 interface
        if interface_name.lower() == "eth0":
            error_msg = "Operation not allowed on eth0 interface - this is the management interface"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        if clab_client.tls:
            if clab_client.cert_path and clab_client.key_path:
                tls_config = docker.tls.TLSConfig(
                    client_cert=(clab_client.cert_path, clab_client.key_path),
                    ca_cert=clab_client.ca_cert_path,
                    verify=True
                )
            else:
                tls_config = docker.tls.TLSConfig(
                    ca_cert=clab_client.ca_cert_path,
                    verify=True
                )
            base_url = f"https://{clab_client.docker_host_ip}:{clab_client.port}"
        else:
            tls_config = None
            base_url = f"tcp://{clab_client.docker_host_ip}:{clab_client.port}"

        # Connect to Docker daemon
        client = docker.DockerClient(base_url=base_url, tls=tls_config)
        
        # Get the container
        container = client.containers.get(container_name)
        
        # Create VLAN interface
        vlan_interface = f"{interface_name}.{vlan_id}"
        
        # Step 1: Create VLAN interface
        try:
            create_vlan_cmd = f"ip link add link {interface_name} name {vlan_interface} type vlan id {vlan_id}"
            exec_result = container.exec_run(create_vlan_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = f"VLAN interface {vlan_interface} created successfully"
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                # Check if interface already exists
                if "File exists" in exec_result.output.decode('utf-8'):
                    info_msg = f"VLAN interface {vlan_interface} already exists"
                    result["messages"].append(info_msg)
                    logger.info(info_msg)
                else:
                    error_msg = f"Failed to create VLAN interface {vlan_interface}: {exec_result.output.decode('utf-8')}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
        except Exception as e:
            error_msg = f"Error creating VLAN interface: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        # Step 2: Bring up the VLAN interface
        try:
            up_cmd = f"ip link set {vlan_interface} up"
            exec_result = container.exec_run(up_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = f"VLAN interface {vlan_interface} brought up successfully"
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                error_msg = f"Failed to bring up VLAN interface {vlan_interface}: {exec_result.output.decode('utf-8')}"
                logger.error(error_msg)
                result["status"] = "error"
                result["error"] = error_msg
                return result
        except Exception as e:
            error_msg = f"Error bringing up VLAN interface: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        # Step 3: Set IP address
        try:
            set_ip_cmd = f"ip addr add {ip_with_mask} dev {vlan_interface}"
            exec_result = container.exec_run(set_ip_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = f"IP address {ip_with_mask} set on {vlan_interface} successfully"
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                # Check if IP already exists
                if "File exists" in exec_result.output.decode('utf-8'):
                    info_msg = f"IP address {ip_with_mask} already exists on {vlan_interface}"
                    result["messages"].append(info_msg)
                    logger.info(info_msg)
                else:
                    error_msg = f"Failed to set IP address {ip_with_mask} on {vlan_interface}: {exec_result.output.decode('utf-8')}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
        except Exception as e:
            error_msg = f"Error setting IP address: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        # Step 4: Set gateway if provided
        if gateway_ip:
            try:
                gateway_cmd = f"ip route add default via {gateway_ip} dev {vlan_interface}"
                exec_result = container.exec_run(gateway_cmd)
                
                if exec_result.exit_code == 0:
                    success_msg = f"Gateway {gateway_ip} set for {vlan_interface} successfully"
                    result["messages"].append(success_msg)
                    logger.info(success_msg)
                else:
                    # Check if route already exists
                    if "File exists" in exec_result.output.decode('utf-8'):
                        info_msg = f"Gateway route via {gateway_ip} already exists"
                        result["messages"].append(info_msg)
                        logger.info(info_msg)
                    else:
                        error_msg = f"Failed to set gateway {gateway_ip}: {exec_result.output.decode('utf-8')}"
                        logger.error(error_msg)
                        result["status"] = "error"
                        result["error"] = error_msg
                        return result
            except Exception as e:
                error_msg = f"Error setting gateway: {str(e)}"
                logger.error(error_msg)
                result["status"] = "error"
                result["error"] = error_msg
                return result
        
        return result
        
    except Exception as e:
        error_msg = f"Unexpected error in set_ip: {str(e)}"
        logger.error(error_msg)
        return {
            "status": "error",
            "container": container_name,
            "interface": interface_name,
            "ip": ip_with_mask,
            "vlan_id": vlan_id,
            "gateway": gateway_ip,
            "error": error_msg
        }
    finally:
        if 'client' in locals():
            client.close()

@mcp.tool
def delete_vlan_interface(
    container_name: str,
    interface_name: str,
    vlan_id: int
) -> Dict:
    """
    Remove a VLAN interface and clean up network configuration from a container.
    
    This tool undoes the network configuration created by the set_ip function by completely
    removing the VLAN interface from the container. When a VLAN interface is deleted:
    1. All IP addresses assigned to the interface are automatically removed
    2. Any routing rules associated with the interface are cleaned up
    3. The interface is taken down and removed from the network namespace
    
    Use this tool when you need to:
    - Clean up network configurations after testing
    - Remove obsolete or misconfigured VLAN interfaces
    - Reset container networking to a clean state
    - Troubleshoot network issues by removing and recreating interfaces
    - Prepare containers for different network configurations
    
    This is the cleanup counterpart to set_ip - use it to remove interfaces that
    were previously created. The tool safely handles cases where the interface
    doesn't exist or has already been removed.
    
    Args:
        container_name: Name of the ContainerLab container to modify
        interface_name: Base interface name (e.g., 'eth1') - the VLAN interface interface_name.vlan_id will be deleted
        vlan_id: VLAN ID number of the interface to delete (must match the original VLAN ID used in set_ip)
    
    Returns:
        Dictionary containing:
        - status: 'success' or 'error'
        - messages: List of cleanup operations performed
        - container, interface, vlan_id: Configuration details
        - error: Error message if operation failed
        
    Raises:
        docker.errors.DockerException: If container is not found or not accessible
        RuntimeError: If interface removal fails due to system constraints
    """
    result = {
        "status": "success",
        "container": container_name,
        "interface": interface_name,
        "vlan_id": vlan_id,
        "messages": []
    }
    
    try:
        if clab_client is None:
            raise RuntimeError("ContainerLab client not initialized. Call initialize_client() first.")
        
        # Protection: Prevent any actions on eth0 interface
        if interface_name.lower() == "eth0":
            error_msg = "Operation not allowed on eth0 interface - this is the management interface"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        if clab_client.tls:
            if clab_client.cert_path and clab_client.key_path:
                tls_config = docker.tls.TLSConfig(
                    client_cert=(clab_client.cert_path, clab_client.key_path),
                    ca_cert=clab_client.ca_cert_path,
                    verify=True
                )
            else:
                tls_config = docker.tls.TLSConfig(
                    ca_cert=clab_client.ca_cert_path,
                    verify=True
                )
            base_url = f"https://{clab_client.docker_host_ip}:{clab_client.port}"
        else:
            tls_config = None
            base_url = f"tcp://{clab_client.docker_host_ip}:{clab_client.port}"

        # Connect to Docker daemon
        client = docker.DockerClient(base_url=base_url, tls=tls_config)
        
        # Get the container
        container = client.containers.get(container_name)
        
        # Delete VLAN interface
        vlan_interface = f"{interface_name}.{vlan_id}"
        
        try:
            delete_vlan_cmd = f"ip link delete {vlan_interface}"
            exec_result = container.exec_run(delete_vlan_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = f"VLAN interface {vlan_interface} deleted successfully"
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                error_msg = f"Failed to delete VLAN interface {vlan_interface}: {exec_result.output.decode('utf-8')}"
                logger.error(error_msg)
                result["status"] = "error"
                result["error"] = error_msg
                return result
        except Exception as e:
            error_msg = f"Error deleting VLAN interface: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        return result
        
    except Exception as e:
        error_msg = f"Unexpected error in delete_vlan_interface: {str(e)}"
        logger.error(error_msg)
        return {
            "status": "error",
            "container": container_name,
            "interface": interface_name,
            "vlan_id": vlan_id,
            "error": error_msg
        }
    finally:
        if 'client' in locals():
            client.close()

@mcp.tool
def test_connectivity(
    container_name: str,
    destination_ip: str
) -> Dict:
    """
    Verify network connectivity between containers or to external destinations using ping.
    
    This tool performs network reachability testing by sending ICMP ping packets from
    a source container to a destination IP address. It provides comprehensive connectivity
    diagnostics including:
    - Success/failure status of ping attempts
    - Round-trip time statistics
    - Packet loss information
    - Network error details if connectivity fails
    
    Use this tool when you need to:
    - Verify that network configuration (set_ip) is working correctly
    - Test connectivity between ContainerLab nodes
    - Diagnose network routing issues
    - Validate VLAN configuration and inter-VLAN communication
    - Troubleshoot network connectivity problems
    - Confirm that containers can reach external networks or services
    
    The tool sends 3 ping packets with a 2-second timeout per packet, providing
    reliable connectivity testing suitable for network validation and troubleshooting.
    
    Args:
        container_name: Name of the source ContainerLab container to ping from
        destination_ip: Target IP address to test connectivity to (can be another container, gateway, or external IP)
        
    Returns:
        Dictionary containing:
        - success: Boolean indicating if ping was successful
        - return_code: Exit code from ping command (0 = success)
        - stdout: Full ping output including statistics
        - stderr: Error messages if ping failed
        - connectivity_status: Human-readable status ('SUCCESS', 'FAILED', 'TIMEOUT', 'ERROR')
        - container_name, destination_ip: Test parameters
        
    Raises:
        subprocess.TimeoutExpired: If ping command takes longer than 10 seconds
        docker.errors.DockerException: If container is not found or not accessible
    """
    try:
        if clab_client is None:
            raise RuntimeError("ContainerLab client not initialized. Call initialize_client() first.")
        
        if clab_client.tls:
            if clab_client.cert_path and clab_client.key_path:
                tls_config = docker.tls.TLSConfig(
                    client_cert=(clab_client.cert_path, clab_client.key_path),
                    ca_cert=clab_client.ca_cert_path,
                    verify=True
                )
            else:
                tls_config = docker.tls.TLSConfig(
                    ca_cert=clab_client.ca_cert_path,
                    verify=True
                )
            base_url = f"https://{clab_client.docker_host_ip}:{clab_client.port}"
        else:
            tls_config = None
            base_url = f"tcp://{clab_client.docker_host_ip}:{clab_client.port}"

        # Connect to Docker daemon
        client = docker.DockerClient(base_url=base_url, tls=tls_config)
        
        # Get the container
        container = client.containers.get(container_name)
        
        # Execute ping command in the container
        exec_result = container.exec_run(
            f"ping -c 3 -W 2 {destination_ip}",
            stdout=True,
            stderr=True
        )
        
        success = exec_result.exit_code == 0
        
        return {
            "success": success,
            "return_code": exec_result.exit_code,
            "stdout": exec_result.output.decode('utf-8') if exec_result.output else "",
            "stderr": "",
            "container_name": container_name,
            "destination_ip": destination_ip,
            "connectivity_status": "SUCCESS" if success else "FAILED"
        }
        
    except Exception as e:
        return {
            "success": False,
            "return_code": -1,
            "stdout": "",
            "stderr": str(e),
            "container_name": container_name,
            "destination_ip": destination_ip,
            "connectivity_status": "ERROR"
        }
    finally:
        if 'client' in locals():
            client.close()

@mcp.tool
def add_static_route(
    container_name: str,
    destination_network: str,
    gateway_ip: str,
    interface_name: str
) -> Dict:
    """
    Add a static route to a ContainerLab container's routing table.
    
    This tool configures static routing within a container by adding a new route entry
    to the container's routing table. It uses the 'ip route add' command to establish
    a path to a specific destination network through a designated gateway and interface.
    
    Static routes are essential for:
    - Directing traffic to specific networks through designated gateways
    - Creating custom routing paths in complex network topologies
    - Enabling communication between isolated network segments
    - Implementing network segmentation and traffic control
    - Supporting multi-homed network configurations
    - Establishing redundant routing paths for network resilience
    
    The tool handles various route configuration scenarios including:
    - Host routes (single IP destinations)
    - Network routes (subnet destinations)
    - Default routes (0.0.0.0/0 destinations)
    - Interface-specific routing
    
    Use this tool when you need to:
    - Configure routing between different network segments
    - For L3 domain testing in ContainerLab
    - Establish connectivity to remote networks
    - Implement custom routing policies
    - Set up network lab scenarios with complex topologies
    - Troubleshoot routing issues by adding specific routes
    - Create network isolation and segmentation
    
    Args:
        container_name: Name of the ContainerLab container to configure routing on
        destination_network: Target network or host in CIDR notation (e.g., '192.168.10.0/24', '10.0.0.1/32', '0.0.0.0/0')
        gateway_ip: IP address of the next-hop gateway router for reaching the destination
        interface_name: Network interface to use for the route (e.g., 'eth1', 'eth1.100')
        
    Returns:
        Dictionary containing:
        - status: 'success' or 'error'
        - messages: List of routing operations performed
        - container, destination_network, gateway_ip, interface: Configuration details
        - error: Error message if operation failed
        - route_command: The exact ip route command that was executed
        
    Raises:
        docker.errors.DockerException: If container is not found or not accessible
        ValueError: If network address format is invalid
        RuntimeError: If route addition fails due to network constraints
    """
    result = {
        "status": "success",
        "container": container_name,
        "destination_network": destination_network,
        "gateway_ip": gateway_ip,
        "interface": interface_name,
        "messages": []
    }
    
    try:
        if clab_client is None:
            raise RuntimeError("ContainerLab client not initialized. Call initialize_client() first.")
        
        if clab_client.tls:
            if clab_client.cert_path and clab_client.key_path:
                tls_config = docker.tls.TLSConfig(
                    client_cert=(clab_client.cert_path, clab_client.key_path),
                    ca_cert=clab_client.ca_cert_path,
                    verify=True
                )
            else:
                tls_config = docker.tls.TLSConfig(
                    ca_cert=clab_client.ca_cert_path,
                    verify=True
                )
            base_url = f"https://{clab_client.docker_host_ip}:{clab_client.port}"
        else:
            tls_config = None
            base_url = f"tcp://{clab_client.docker_host_ip}:{clab_client.port}"

        # Connect to Docker daemon
        client = docker.DockerClient(base_url=base_url, tls=tls_config)
        
        # Get the container
        container = client.containers.get(container_name)
        
        # Construct the ip route add command
        route_cmd = f"ip route add {destination_network} via {gateway_ip} dev {interface_name}"
        result["route_command"] = route_cmd
        
        try:
            exec_result = container.exec_run(route_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = f"Static route added successfully: {destination_network} via {gateway_ip} dev {interface_name}"
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                error_output = exec_result.output.decode('utf-8').strip()
                
                # Check for common route errors and provide helpful messages
                if "File exists" in error_output:
                    info_msg = f"Route to {destination_network} via {gateway_ip} already exists"
                    result["messages"].append(info_msg)
                    logger.info(info_msg)
                elif "Network is unreachable" in error_output:
                    error_msg = f"Gateway {gateway_ip} is not reachable from interface {interface_name}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
                elif "No such device" in error_output:
                    error_msg = f"Interface {interface_name} does not exist in container {container_name}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
                elif "Invalid argument" in error_output:
                    error_msg = f"Invalid route parameters: {error_output}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
                else:
                    error_msg = f"Failed to add static route: {error_output}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
        except Exception as e:
            error_msg = f"Error executing route command: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        return result
        
    except Exception as e:
        error_msg = f"Unexpected error in add_static_route: {str(e)}"
        logger.error(error_msg)
        return {
            "status": "error",
            "container": container_name,
            "destination_network": destination_network,
            "gateway_ip": gateway_ip,
            "interface": interface_name,
            "error": error_msg
        }
    finally:
        if 'client' in locals():
            client.close()

if __name__ == "__main__":
    # Initialize the client
    initialize_client()
    
    # Run the FastMCP server
    mcp.run(transport="http", host="0.0.0.0", port=8989,log_level="debug")
