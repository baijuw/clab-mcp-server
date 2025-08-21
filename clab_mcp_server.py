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
import os
import argparse
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

def initialize_client(docker_host_ip: str = None, port: int = None, tls: bool = False):
    """Initialize the global ContainerLabClient instance."""
    global clab_client
    
    # Use environment variable if docker_host_ip not provided
    if docker_host_ip is None:
        docker_host_ip = os.getenv('DOCKER_HOST_IP', 'localhost')
    
    # Use environment variable if port not provided
    if port is None:
        port = int(os.getenv('DOCKER_PORT', '2375'))
    
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
    
    Troubleshooting ping failures:
    - Same subnet (L2): If the remote IP is in the same subnet and the ping fails, check that 
      the BridgeDomain type is EVPNVXLAN. When the L2 domain is stretched across leaf switches, 
      a BridgeDomain type of SIMPLE will not establish connectivity.
    - Different subnet (L3): If the remote IP is in a different subnet, first ensure that a 
      route exists on both the client for connectivity (either a specific route to the 
      destination or a default route).
    
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
def create_bond_interface(
    container_name: str,
    bond_name: str,
    slave_interfaces: List[str],
    bond_mode: str = "active-backup",
    miimon: int = 100
) -> Dict:
    """
    Create a bond interface in a ContainerLab container for network redundancy and load balancing.
    
    This tool creates a bonded network interface by combining multiple physical interfaces
    into a single logical interface. Bond interfaces provide:
    - Network redundancy (failover protection)
    - Load balancing across multiple links
    - Increased bandwidth aggregation
    - High availability networking
    
    The tool performs the following operations:
    1. Creates a new bond interface with specified name
    2. Configures the bonding mode and monitoring parameters
    3. Adds slave interfaces to the bond
    4. Brings up the bond interface and slave interfaces
    
    Common bonding modes:
    - active-backup: One interface active, others standby (fault tolerance)
    - balance-rr: Round-robin load balancing
    - balance-xor: XOR hash load balancing
    - broadcast: Transmit on all interfaces
    - 802.3ad: IEEE 802.3ad dynamic link aggregation (LACP)
    - balance-tlb: Adaptive transmit load balancing
    - balance-alb: Adaptive load balancing
    
    Use this tool when you need to:
    - Create redundant network connections for high availability
    - Aggregate bandwidth from multiple interfaces
    - Implement network load balancing
    - Set up fault-tolerant network configurations
    - Test network failover scenarios in lab environments
    - Configure LACP (802.3ad) aggregation
    
    Args:
        container_name: Name of the ContainerLab container to configure
        bond_name: Name for the new bond interface (e.g., 'bond0', 'bond1')
        slave_interfaces: List of interface names to add to the bond (e.g., ['eth1', 'eth2'])
        bond_mode: Bonding mode - options: active-backup, balance-rr, balance-xor, broadcast, 802.3ad, balance-tlb, balance-alb (default: 'active-backup')
        miimon: MII monitoring interval in milliseconds (default: 100)
    
    Returns:
        Dictionary containing:
        - status: 'success' or 'error'
        - messages: List of configuration steps performed
        - bond_name, slave_interfaces, bond_mode, miimon: Configuration details
        - container: Container name
        - error: Error message if operation failed
        
    Raises:
        docker.errors.DockerException: If container is not found or not accessible
        ValueError: If slave interfaces are invalid or bond mode is unsupported
        RuntimeError: If bond creation fails due to system constraints
    """
    result = {
        "status": "success",
        "container": container_name,
        "bond_name": bond_name,
        "slave_interfaces": slave_interfaces,
        "bond_mode": bond_mode,
        "miimon": miimon,
        "messages": []
    }
    
    try:
        if clab_client is None:
            raise RuntimeError("ContainerLab client not initialized. Call initialize_client() first.")
        
        # Validate inputs
        if not slave_interfaces or len(slave_interfaces) < 2:
            error_msg = "At least 2 slave interfaces are required for bonding"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        # Validate bond mode
        valid_modes = ["active-backup", "balance-rr", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"]
        if bond_mode not in valid_modes:
            error_msg = f"Invalid bond mode '{bond_mode}'. Valid modes: {', '.join(valid_modes)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        # Protection: Prevent any actions on eth0 interface
        for interface in slave_interfaces:
            if interface.lower() == "eth0":
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
        
        # Step 1: Load bonding module (if not already loaded)
        try:
            modprobe_cmd = "modprobe bonding"
            exec_result = container.exec_run(modprobe_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = "Bonding module loaded successfully"
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                # Module might already be loaded, check if it's just a warning
                output = exec_result.output.decode('utf-8') if exec_result.output else ""
                if "already loaded" not in output.lower():
                    warn_msg = f"Bonding module load warning: {output}"
                    result["messages"].append(warn_msg)
                    logger.warning(warn_msg)
        except Exception as e:
            error_msg = f"Error loading bonding module: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        # Step 2: Create bond interface
        try:
            create_bond_cmd = f"ip link add {bond_name} type bond mode {bond_mode} miimon {miimon}"
            exec_result = container.exec_run(create_bond_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = f"Bond interface {bond_name} created successfully with mode {bond_mode}"
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                # Check if interface already exists
                output = exec_result.output.decode('utf-8') if exec_result.output else ""
                if "File exists" in output:
                    info_msg = f"Bond interface {bond_name} already exists"
                    result["messages"].append(info_msg)
                    logger.info(info_msg)
                else:
                    error_msg = f"Failed to create bond interface {bond_name}: {output}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
        except Exception as e:
            error_msg = f"Error creating bond interface: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        # Step 3: Add slave interfaces to bond
        for slave_interface in slave_interfaces:
            try:
                # First, bring down the slave interface
                down_cmd = f"ip link set {slave_interface} down"
                exec_result = container.exec_run(down_cmd)
                
                if exec_result.exit_code == 0:
                    msg = f"Interface {slave_interface} brought down"
                    result["messages"].append(msg)
                    logger.info(msg)
                
                # Add slave to bond
                add_slave_cmd = f"ip link set {slave_interface} master {bond_name}"
                exec_result = container.exec_run(add_slave_cmd)
                
                if exec_result.exit_code == 0:
                    success_msg = f"Added {slave_interface} as slave to bond {bond_name}"
                    result["messages"].append(success_msg)
                    logger.info(success_msg)
                else:
                    error_msg = f"Failed to add {slave_interface} to bond {bond_name}: {exec_result.output.decode('utf-8')}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
                
                # Bring slave interface back up
                up_cmd = f"ip link set {slave_interface} up"
                exec_result = container.exec_run(up_cmd)
                
                if exec_result.exit_code == 0:
                    msg = f"Interface {slave_interface} brought up as bond slave"
                    result["messages"].append(msg)
                    logger.info(msg)
                
            except Exception as e:
                error_msg = f"Error adding slave interface {slave_interface}: {str(e)}"
                logger.error(error_msg)
                result["status"] = "error"
                result["error"] = error_msg
                return result
        
        # Step 4: Bring up the bond interface
        try:
            up_bond_cmd = f"ip link set {bond_name} up"
            exec_result = container.exec_run(up_bond_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = f"Bond interface {bond_name} brought up successfully"
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                error_msg = f"Failed to bring up bond interface {bond_name}: {exec_result.output.decode('utf-8')}"
                logger.error(error_msg)
                result["status"] = "error"
                result["error"] = error_msg
                return result
        except Exception as e:
            error_msg = f"Error bringing up bond interface: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        return result
        
    except Exception as e:
        error_msg = f"Unexpected error in create_bond_interface: {str(e)}"
        logger.error(error_msg)
        return {
            "status": "error",
            "container": container_name,
            "bond_name": bond_name,
            "slave_interfaces": slave_interfaces,
            "bond_mode": bond_mode,
            "miimon": miimon,
            "error": error_msg
        }
    finally:
        if 'client' in locals():
            client.close()

@mcp.tool
def delete_bond_interface(
    container_name: str,
    bond_name: str,
    slave_interfaces: List[str]
) -> Dict:
    """
    Delete a bond interface and restore slave interfaces to their original state.
    
    This tool reverses the configuration created by create_bond_interface by:
    1. Bringing down the bond interface
    2. Removing slave interfaces from the bond
    3. Deleting the bond interface
    4. Bringing slave interfaces back up as independent interfaces
    
    This is the cleanup counterpart to create_bond_interface - use it to remove
    bonded interfaces and restore the original network configuration. The tool
    safely handles cases where the bond doesn't exist or slaves have already
    been removed.
    
    Use this tool when you need to:
    - Clean up bond configurations after testing
    - Remove obsolete or misconfigured bond interfaces
    - Restore original interface configurations
    - Troubleshoot bonding issues by removing and recreating bonds
    - Prepare containers for different network configurations
    - Convert from bonded to individual interface configurations
    
    Args:
        container_name: Name of the ContainerLab container to modify
        bond_name: Name of the bond interface to delete (e.g., 'bond0', 'bond1')
        slave_interfaces: List of slave interface names to restore (e.g., ['eth1', 'eth2'])
    
    Returns:
        Dictionary containing:
        - status: 'success' or 'error'
        - messages: List of cleanup operations performed
        - bond_name, slave_interfaces: Configuration details
        - container: Container name
        - error: Error message if operation failed
        
    Raises:
        docker.errors.DockerException: If container is not found or not accessible
        RuntimeError: If bond deletion fails due to system constraints
    """
    result = {
        "status": "success",
        "container": container_name,
        "bond_name": bond_name,
        "slave_interfaces": slave_interfaces,
        "messages": []
    }
    
    try:
        if clab_client is None:
            raise RuntimeError("ContainerLab client not initialized. Call initialize_client() first.")
        
        # Protection: Prevent any actions on eth0 interface
        for interface in slave_interfaces:
            if interface.lower() == "eth0":
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
        
        # Step 1: Bring down the bond interface
        try:
            down_bond_cmd = f"ip link set {bond_name} down"
            exec_result = container.exec_run(down_bond_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = f"Bond interface {bond_name} brought down successfully"
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                output = exec_result.output.decode('utf-8') if exec_result.output else ""
                if "Cannot find device" in output:
                    info_msg = f"Bond interface {bond_name} does not exist or already removed"
                    result["messages"].append(info_msg)
                    logger.info(info_msg)
                else:
                    warn_msg = f"Warning bringing down bond interface {bond_name}: {output}"
                    result["messages"].append(warn_msg)
                    logger.warning(warn_msg)
        except Exception as e:
            error_msg = f"Error bringing down bond interface: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        # Step 2: Remove slave interfaces from bond and restore them
        for slave_interface in slave_interfaces:
            try:
                # Remove slave from bond (this also brings the interface down)
                remove_slave_cmd = f"ip link set {slave_interface} nomaster"
                exec_result = container.exec_run(remove_slave_cmd)
                
                if exec_result.exit_code == 0:
                    success_msg = f"Removed {slave_interface} from bond {bond_name}"
                    result["messages"].append(success_msg)
                    logger.info(success_msg)
                else:
                    output = exec_result.output.decode('utf-8') if exec_result.output else ""
                    if "Cannot find device" in output:
                        warn_msg = f"Interface {slave_interface} not found or already removed from bond"
                        result["messages"].append(warn_msg)
                        logger.warning(warn_msg)
                    else:
                        warn_msg = f"Warning removing {slave_interface} from bond: {output}"
                        result["messages"].append(warn_msg)
                        logger.warning(warn_msg)
                
                # Bring slave interface back up as independent interface
                up_cmd = f"ip link set {slave_interface} up"
                exec_result = container.exec_run(up_cmd)
                
                if exec_result.exit_code == 0:
                    success_msg = f"Interface {slave_interface} restored as independent interface"
                    result["messages"].append(success_msg)
                    logger.info(success_msg)
                else:
                    output = exec_result.output.decode('utf-8') if exec_result.output else ""
                    warn_msg = f"Warning bringing up {slave_interface}: {output}"
                    result["messages"].append(warn_msg)
                    logger.warning(warn_msg)
                
            except Exception as e:
                error_msg = f"Error restoring slave interface {slave_interface}: {str(e)}"
                logger.error(error_msg)
                result["status"] = "error"
                result["error"] = error_msg
                return result
        
        # Step 3: Delete the bond interface
        try:
            delete_bond_cmd = f"ip link delete {bond_name}"
            exec_result = container.exec_run(delete_bond_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = f"Bond interface {bond_name} deleted successfully"
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                output = exec_result.output.decode('utf-8') if exec_result.output else ""
                if "Cannot find device" in output:
                    info_msg = f"Bond interface {bond_name} does not exist or already deleted"
                    result["messages"].append(info_msg)
                    logger.info(info_msg)
                else:
                    error_msg = f"Failed to delete bond interface {bond_name}: {output}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
        except Exception as e:
            error_msg = f"Error deleting bond interface: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        return result
        
    except Exception as e:
        error_msg = f"Unexpected error in delete_bond_interface: {str(e)}"
        logger.error(error_msg)
        return {
            "status": "error",
            "container": container_name,
            "bond_name": bond_name,
            "slave_interfaces": slave_interfaces,
            "error": error_msg
        }
    finally:
        if 'client' in locals():
            client.close()

@mcp.tool
def get_interface_info(
    container_name: str,
    interface_name: str
) -> Dict:
    """
    Retrieve comprehensive configuration and status information for a network interface.
    
    This tool provides detailed inspection of network interfaces including:
    - Basic interface properties (state, MAC address, MTU)
    - IP address configuration and VLAN information
    - Bond interface details (mode, slaves, active slave status)
    - Interface statistics and operational status
    - Routing information related to the interface
    
    For bonded interfaces, the tool provides specialized bond information including:
    - Bond mode and configuration parameters
    - Slave interface status and active/backup states
    - MII monitoring status and link state
    - Failover and load balancing configuration
    
    Use this tool when you need to:
    - Verify interface configuration after using set_ip or create_bond_interface
    - Troubleshoot network connectivity issues
    - Validate bond interface status and slave configurations
    - Check interface operational state and statistics
    - Perform post-configuration verification and assurance
    - Debug network problems and interface inconsistencies
    - Monitor interface health and performance
    
    This is essential for network troubleshooting and configuration validation,
    providing comprehensive visibility into interface status and configuration.
    
    Args:
        container_name: Name of the ContainerLab container to inspect
        interface_name: Name of the interface to analyze (e.g., 'eth1', 'bond0', 'eth1.100')
    
    Returns:
        Dictionary containing:
        - interface_name, container: Input parameters
        - exists: Boolean indicating if interface exists
        - interface_type: Type of interface ('physical', 'vlan', 'bond', 'unknown')
        - state: Interface operational state ('up', 'down', 'unknown')
        - mac_address: Hardware MAC address
        - mtu: Maximum transmission unit
        - ip_addresses: List of configured IP addresses with CIDR notation
        - bond_info: Bond-specific information (if interface is bonded)
          - mode: Bond mode (active-backup, balance-rr, etc.)
          - slaves: List of slave interfaces with their status
          - active_slave: Currently active slave interface
          - mii_status: MII monitoring status
        - vlan_info: VLAN-specific information (if interface is VLAN)
          - vlan_id: VLAN ID number
          - parent_interface: Parent physical interface
        - statistics: Interface traffic statistics
        - error: Error message if inspection failed
        
    Raises:
        docker.errors.DockerException: If container is not found or not accessible
        RuntimeError: If interface inspection commands fail
    """
    result = {
        "container": container_name,
        "interface_name": interface_name,
        "exists": False,
        "interface_type": "unknown",
        "state": "unknown",
        "mac_address": None,
        "mtu": None,
        "ip_addresses": [],
        "bond_info": None,
        "vlan_info": None,
        "statistics": None,
        "error": None
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
        
        # Step 1: Get basic interface information using 'ip link show'
        try:
            ip_link_cmd = f"ip -j link show {interface_name}"
            exec_result = container.exec_run(ip_link_cmd)
            
            if exec_result.exit_code == 0:
                try:
                    link_info = json.loads(exec_result.output.decode('utf-8').strip())
                    if link_info:
                        interface_data = link_info[0]
                        result["exists"] = True
                        result["state"] = "up" if "UP" in interface_data.get("flags", []) else "down"
                        result["mac_address"] = interface_data.get("address")
                        result["mtu"] = interface_data.get("mtu")
                        
                        # Determine interface type
                        link_type = interface_data.get("linkinfo", {}).get("info_kind")
                        if link_type == "bond":
                            result["interface_type"] = "bond"
                        elif link_type == "vlan":
                            result["interface_type"] = "vlan"
                        elif "." in interface_name:
                            result["interface_type"] = "vlan"
                        else:
                            result["interface_type"] = "physical"
                            
                except json.JSONDecodeError:
                    result["error"] = f"Failed to parse interface link information"
                    return result
            else:
                # Interface doesn't exist
                result["error"] = f"Interface {interface_name} does not exist"
                return result
                
        except Exception as e:
            result["error"] = f"Error getting interface link info: {str(e)}"
            return result
        
        # Step 2: Get IP address information using 'ip addr show'
        try:
            ip_addr_cmd = f"ip -j addr show {interface_name}"
            exec_result = container.exec_run(ip_addr_cmd)
            
            if exec_result.exit_code == 0:
                try:
                    addr_info = json.loads(exec_result.output.decode('utf-8').strip())
                    if addr_info:
                        addr_data = addr_info[0]
                        addresses = []
                        for addr in addr_data.get("addr_info", []):
                            if addr.get("family") == "inet":  # IPv4
                                ip_with_prefix = f"{addr.get('local')}/{addr.get('prefixlen')}"
                                addresses.append(ip_with_prefix)
                        result["ip_addresses"] = addresses
                        
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse IP address info for {interface_name}")
                    
        except Exception as e:
            logger.warning(f"Error getting IP address info: {str(e)}")
        
        # Step 3: Get bond-specific information if this is a bond interface
        if result["interface_type"] == "bond":
            bond_info = {
                "mode": None,
                "slaves": [],
                "active_slave": None,
                "mii_status": None
            }
            
            try:
                # Get bond mode
                mode_cmd = f"cat /proc/net/bonding/{interface_name}"
                exec_result = container.exec_run(mode_cmd)
                
                if exec_result.exit_code == 0:
                    bond_status = exec_result.output.decode('utf-8')
                    
                    # Parse bond mode
                    for line in bond_status.split('\n'):
                        if line.startswith('Bonding Mode:'):
                            bond_info["mode"] = line.split(':', 1)[1].strip()
                        elif line.startswith('Currently Active Slave:'):
                            bond_info["active_slave"] = line.split(':', 1)[1].strip()
                        elif line.startswith('MII Status:'):
                            bond_info["mii_status"] = line.split(':', 1)[1].strip()
                    
                    # Parse slave information
                    slaves = []
                    current_slave = None
                    for line in bond_status.split('\n'):
                        if line.startswith('Slave Interface:'):
                            if current_slave:
                                slaves.append(current_slave)
                            current_slave = {
                                "name": line.split(':', 1)[1].strip(),
                                "status": "unknown",
                                "link": "unknown"
                            }
                        elif current_slave and line.startswith('MII Status:'):
                            current_slave["status"] = line.split(':', 1)[1].strip()
                        elif current_slave and line.startswith('Link Failure Count:'):
                            # Additional slave info can be added here
                            pass
                    
                    if current_slave:
                        slaves.append(current_slave)
                    
                    bond_info["slaves"] = slaves
                    
            except Exception as e:
                logger.warning(f"Error getting bond info: {str(e)}")
                bond_info["error"] = str(e)
            
            result["bond_info"] = bond_info
        
        # Step 4: Get VLAN-specific information if this is a VLAN interface
        elif result["interface_type"] == "vlan":
            vlan_info = {
                "vlan_id": None,
                "parent_interface": None
            }
            
            try:
                # Parse VLAN ID from interface name (e.g., eth1.100 -> VLAN 100)
                if "." in interface_name:
                    parts = interface_name.split(".")
                    if len(parts) == 2:
                        vlan_info["parent_interface"] = parts[0]
                        try:
                            vlan_info["vlan_id"] = int(parts[1])
                        except ValueError:
                            pass
                
                # Alternative: get VLAN info from ip link show output
                ip_link_detail_cmd = f"ip -d link show {interface_name}"
                exec_result = container.exec_run(ip_link_detail_cmd)
                
                if exec_result.exit_code == 0:
                    link_detail = exec_result.output.decode('utf-8')
                    # Parse additional VLAN details if needed
                    for line in link_detail.split('\n'):
                        if 'vlan' in line and 'id' in line:
                            # Extract VLAN ID from detailed output
                            import re
                            vlan_match = re.search(r'vlan id (\d+)', line)
                            if vlan_match:
                                vlan_info["vlan_id"] = int(vlan_match.group(1))
                            
            except Exception as e:
                logger.warning(f"Error getting VLAN info: {str(e)}")
            
            result["vlan_info"] = vlan_info
        
        # Step 5: Get interface statistics
        try:
            stats_cmd = f"ip -j -s link show {interface_name}"
            exec_result = container.exec_run(stats_cmd)
            
            if exec_result.exit_code == 0:
                try:
                    stats_info = json.loads(exec_result.output.decode('utf-8').strip())
                    if stats_info and stats_info[0].get("stats64"):
                        stats = stats_info[0]["stats64"]
                        result["statistics"] = {
                            "rx_packets": stats.get("rx", {}).get("packets"),
                            "tx_packets": stats.get("tx", {}).get("packets"), 
                            "rx_bytes": stats.get("rx", {}).get("bytes"),
                            "tx_bytes": stats.get("tx", {}).get("bytes"),
                            "rx_errors": stats.get("rx", {}).get("errors"),
                            "tx_errors": stats.get("tx", {}).get("errors"),
                            "rx_dropped": stats.get("rx", {}).get("dropped"),
                            "tx_dropped": stats.get("tx", {}).get("dropped")
                        }
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse interface statistics for {interface_name}")
                    
        except Exception as e:
            logger.warning(f"Error getting interface statistics: {str(e)}")
        
        return result
        
    except Exception as e:
        error_msg = f"Unexpected error in get_interface_info: {str(e)}"
        logger.error(error_msg)
        result["error"] = error_msg
        return result
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

@mcp.tool
def check_routes(
    container_name: str,
    destination_filter: Optional[str] = None
) -> Dict:
    """
    Retrieve the routing table from a ContainerLab container for network troubleshooting.
    
    This tool displays the container's routing table using the 'ip route show' command,
    providing comprehensive visibility into how traffic is routed within the container.
    The routing table shows:
    - Destination networks and host routes
    - Gateway/next-hop IP addresses
    - Outgoing network interfaces for each route
    - Route metrics and administrative distances
    - Default routes and network-specific routes
    
    This information is essential for:
    - Troubleshooting inter-VLAN connectivity issues
    - Verifying static route configurations added with add_static_route
    - Understanding traffic flow paths in complex network topologies
    - Diagnosing routing problems between network segments
    - Validating network configuration in lab environments
    - Confirming that containers have appropriate routes to reach destinations
    
    Use this tool when you need to:
    - Verify that static routes have been properly configured
    - Troubleshoot connectivity issues between different VLANs or subnets
    - Understand how traffic flows from a container to various destinations
    - Debug routing problems in multi-homed network configurations
    - Validate routing table entries after network configuration changes
    - Analyze routing paths for network optimization
    - Confirm default gateway configurations
    
    The tool optionally allows filtering routes to specific destinations, which is
    helpful when troubleshooting connectivity to particular networks or hosts.
    
    Args:
        container_name: Name of the ContainerLab container to query routing table from
        destination_filter: Optional destination network or IP to filter routes (e.g., '192.168.10.0/24', '10.0.0.1', 'default')
        
    Returns:
        Dictionary containing:
        - status: 'success' or 'error'
        - container: Container name
        - routes: List of route entries with destination, gateway, interface, and additional details
        - raw_output: Raw text output from 'ip route show' command
        - filter_applied: The destination filter that was applied (if any)
        - route_count: Number of routes found
        - error: Error message if operation failed
        
    Raises:
        docker.errors.DockerException: If container is not found or not accessible
        RuntimeError: If routing table query fails
    """
    result = {
        "status": "success",
        "container": container_name,
        "routes": [],
        "raw_output": "",
        "filter_applied": destination_filter,
        "route_count": 0,
        "error": None
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
        
        # Construct the ip route show command with optional filtering
        if destination_filter:
            route_cmd = f"ip route show {destination_filter}"
        else:
            route_cmd = "ip route show"
        
        try:
            exec_result = container.exec_run(
                route_cmd,
                stdout=True,
                stderr=True
            )
            
            if exec_result.exit_code == 0:
                raw_output = exec_result.output.decode('utf-8').strip()
                result["raw_output"] = raw_output
                
                # Parse the routing table output
                routes = []
                if raw_output:
                    for line in raw_output.split('\n'):
                        if line.strip():
                            route_entry = {
                                "raw_line": line.strip(),
                                "destination": None,
                                "gateway": None,
                                "interface": None,
                                "metric": None,
                                "protocol": None,
                                "scope": None
                            }
                            
                            # Parse route components
                            parts = line.strip().split()
                            if parts:
                                # First part is usually the destination
                                if parts[0] in ['default', '0.0.0.0/0']:
                                    route_entry["destination"] = "default (0.0.0.0/0)"
                                else:
                                    route_entry["destination"] = parts[0]
                                
                                # Look for key-value pairs in the route line
                                i = 1
                                while i < len(parts):
                                    if parts[i] == "via" and i + 1 < len(parts):
                                        route_entry["gateway"] = parts[i + 1]
                                        i += 2
                                    elif parts[i] == "dev" and i + 1 < len(parts):
                                        route_entry["interface"] = parts[i + 1]
                                        i += 2
                                    elif parts[i] == "metric" and i + 1 < len(parts):
                                        route_entry["metric"] = parts[i + 1]
                                        i += 2
                                    elif parts[i] == "proto" and i + 1 < len(parts):
                                        route_entry["protocol"] = parts[i + 1]
                                        i += 2
                                    elif parts[i] == "scope" and i + 1 < len(parts):
                                        route_entry["scope"] = parts[i + 1]
                                        i += 2
                                    else:
                                        i += 1
                            
                            routes.append(route_entry)
                
                result["routes"] = routes
                result["route_count"] = len(routes)
                
                logger.info(f"Successfully retrieved {len(routes)} routes from container {container_name}")
                
            else:
                error_output = exec_result.output.decode('utf-8').strip()
                error_msg = f"Failed to retrieve routing table: {error_output}"
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
        error_msg = f"Unexpected error in check_routes: {str(e)}"
        logger.error(error_msg)
        return {
            "status": "error",
            "container": container_name,
            "filter_applied": destination_filter,
            "error": error_msg
        }
    finally:
        if 'client' in locals():
            client.close()

@mcp.tool
def route_delete(
    container_name: str,
    destination_network: str,
    gateway_ip: Optional[str] = None,
    interface_name: Optional[str] = None
) -> Dict:
    """
    Delete a static route from a ContainerLab container's routing table.
    
    This tool removes specific routes from a container's routing table using the 'ip route del' command.
    It provides flexible route deletion options by allowing specification of:
    - Destination network only (removes all routes to that destination)
    - Destination network with specific gateway (removes route via specific gateway)
    - Destination network with specific interface (removes route via specific interface)
    - Complete route specification (destination, gateway, and interface)
    
    This is the cleanup counterpart to add_static_route - use it to remove routes that
    are no longer needed or were incorrectly configured. The tool handles various
    route deletion scenarios and provides detailed feedback on the operation.
    
    Use this tool when you need to:
    - Remove obsolete or incorrect static routes
    - Clean up routing tables after network testing
    - Modify routing configurations by removing old routes before adding new ones
    - Troubleshoot routing issues by removing conflicting routes
    - Restore default routing behavior by removing custom routes
    - Prepare containers for different network configurations
    - Remove routes that are causing connectivity problems
    
    The tool supports partial route specification, allowing flexible deletion of routes
    based on available information. For example, you can delete all routes to a specific
    destination without specifying the gateway or interface.
    
    Args:
        container_name: Name of the ContainerLab container to modify routing table
        destination_network: Target network or host in CIDR notation to remove routes for (e.g., '192.168.10.0/24', '10.0.0.1/32', '0.0.0.0/0')
        gateway_ip: Optional gateway IP to match for route deletion (if not specified, matches any gateway)
        interface_name: Optional interface name to match for route deletion (if not specified, matches any interface)
        
    Returns:
        Dictionary containing:
        - status: 'success' or 'error'
        - messages: List of route deletion operations performed
        - container, destination_network, gateway_ip, interface: Configuration details
        - error: Error message if operation failed
        - route_command: The exact ip route command that was executed
        
    Raises:
        docker.errors.DockerException: If container is not found or not accessible
        ValueError: If network address format is invalid
        RuntimeError: If route deletion fails due to network constraints
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
        
        # Construct the ip route del command based on provided parameters
        route_cmd_parts = ["ip", "route", "del", destination_network]
        
        if gateway_ip:
            route_cmd_parts.extend(["via", gateway_ip])
        
        if interface_name:
            route_cmd_parts.extend(["dev", interface_name])
        
        route_cmd = " ".join(route_cmd_parts)
        result["route_command"] = route_cmd
        
        try:
            exec_result = container.exec_run(route_cmd)
            
            if exec_result.exit_code == 0:
                success_msg = f"Static route deleted successfully: {destination_network}"
                if gateway_ip:
                    success_msg += f" via {gateway_ip}"
                if interface_name:
                    success_msg += f" dev {interface_name}"
                
                result["messages"].append(success_msg)
                logger.info(success_msg)
            else:
                error_output = exec_result.output.decode('utf-8').strip()
                
                # Check for common route deletion errors and provide helpful messages
                if "No such process" in error_output or "ESRCH" in error_output:
                    error_msg = f"Route to {destination_network} does not exist"
                    if gateway_ip:
                        error_msg += f" via gateway {gateway_ip}"
                    if interface_name:
                        error_msg += f" through interface {interface_name}"
                    
                    logger.warning(error_msg)
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
                    error_msg = f"Invalid route deletion parameters: {error_output}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
                elif "Operation not permitted" in error_output:
                    error_msg = f"Permission denied - cannot delete route: {error_output}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
                else:
                    error_msg = f"Failed to delete static route: {error_output}"
                    logger.error(error_msg)
                    result["status"] = "error"
                    result["error"] = error_msg
                    return result
        except Exception as e:
            error_msg = f"Error executing route deletion command: {str(e)}"
            logger.error(error_msg)
            result["status"] = "error"
            result["error"] = error_msg
            return result
        
        return result
        
    except Exception as e:
        error_msg = f"Unexpected error in route_delete: {str(e)}"
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
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='ContainerLab MCP Server')
    parser.add_argument('--docker-host-ip', type=str, default=None,
                        help='Docker host IP address (default: localhost, or set DOCKER_HOST_IP env var)')
    parser.add_argument('--docker-port', type=int, default=2375,
                        help='Docker daemon port (default: 2375)')
    parser.add_argument('--docker-tls', action='store_true', default=False,
                        help='Use TLS for Docker connection (default: False)')
    parser.add_argument('--mcp-host', type=str, default="0.0.0.0",
                        help='MCP server host (default: 0.0.0.0)')
    parser.add_argument('--mcp-port', type=int, default=8989,
                        help='MCP server port (default: 8989)')
    
    args = parser.parse_args()
    
    # Initialize the client with provided arguments
    initialize_client(docker_host_ip=args.docker_host_ip, port=args.docker_port, tls=args.docker_tls)
    
    # Run the FastMCP server
    mcp.run(transport="http", host=args.mcp_host, port=args.mcp_port, log_level="debug")
