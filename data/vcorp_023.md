# Privileged Container Execution Due to Missing USER Directive

# Vulnerability Case
During our internal assessment of Acme Corp's containerized microservices, we discovered that a critical Docker image used for a Node.js web server was built from a Dockerfile that omits the `USER` directive. This omission results in the application processes running as the root user, which can be exploited if an attacker gains code execution within the container. The vulnerability was identified during a review of the CI/CD pipeline where standard Dockerfiles based on the Ubuntu and Node.js stacks were used without enforcing least privilege policies. Running processes as root can allow attackers to escalate privileges, potentially enabling lateral movement or container escape in environments misconfigured with relaxed isolation.

```dockerfile
# Dockerfile snippet missing the non-root USER directive
FROM node:14
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install
COPY . .
CMD ["node", "server.js"]
```

The absence of a non-root `USER` declaration in the Dockerfile creates a scenario where every process inside the container is executed with root privileges by default. An attacker exploiting vulnerabilities in the Node.js application—such as remote code execution or command injection—could leverage these privileges to manipulate the container's filesystem or environment. This escalation could lead to accessing host-mounted volumes or other sensitive resources, increasing the risk of container breakout and broader infrastructure compromise. In production environments, such misconfigurations directly impact the business by exposing critical systems to potential data breaches and operational disruptions.

context: dockerfile.security.missing-user.missing-user By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'.

# Vulnerability Breakdown
This vulnerability stems from a critical security misconfiguration in Acme Corp's Docker images where the containers run with root privileges due to omitting the USER directive in the Dockerfile.

1. **Key vulnerability elements**:
   - Docker containers run as the root user by default when no USER is specified
   - Critical Node.js web server images built without proper privilege constraints
   - Container processes executing with excessive permissions
   - Potential for privilege escalation and container escape if application is compromised
   - Security best practice of least privilege violated in containerized environment

2. **Potential attack vectors**:
   - Exploitation of Node.js application vulnerabilities to gain initial container access
   - Leveraging root privileges to access sensitive host-mounted volumes
   - Exploiting container runtime vulnerabilities to escape container boundaries
   - Accessing and manipulating shared Docker socket if mounted
   - Utilizing root privileges to establish persistence mechanisms

3. **Severity assessment**:
   - While requiring initial access to the container (local attack vector), exploitation is straightforward
   - The scope changes from container to potentially affecting the host environment
   - High impact across confidentiality, integrity, and availability
   - Minimal privileges required to initiate the attack if vulnerability exists in application
   - No user interaction needed for exploitation

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Local (L) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A security vulnerability has been identified in Acme Corp's containerized microservices, specifically in a critical Docker image used for a Node.js web server. The Dockerfile omits the `USER` directive, resulting in all container processes running with root privileges. This misconfiguration violates the principle of least privilege and creates significant security risks.

```dockerfile
# Dockerfile snippet missing the non-root USER directive
FROM node:14
WORKPLACE /app
COPY package.json package-lock.json ./
RUN npm install
COPY . .
CMD ["node", "server.js"]

```

Running container processes as root significantly increases the attack surface. If an attacker exploits vulnerabilities in the Node.js application to gain code execution, they would immediately have root-level privileges within the container. This privileged access could enable container escape, access to sensitive host resources, and other escalation scenarios in environments with relaxed isolation configurations. The issue was identified during a review of the CI/CD pipeline where standard Docker images based on Ubuntu and Node.js stacks were being used without enforcing least privilege security practices.

# CVSS
**Score**: 8.8 \
**Vector**: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H \
**Severity**: High

The High severity rating (8.8) for this vulnerability is justified by several critical factors:

- **Local Attack Vector (AV:L)**: The vulnerability requires the attacker to first gain access to the container, typically by exploiting another vulnerability in the application. This local access requirement slightly reduces the overall risk compared to remotely exploitable vulnerabilities.

- **Low Attack Complexity (AC:L)**: Once an attacker has access to the container, exploiting the root privileges is straightforward and doesn't require special conditions or preparation.

- **Low Privileges Required (PR:L)**: An attacker only needs minimal privileges to initially access the container before leveraging the root-level execution.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without requiring any actions from legitimate users of the system.

- **Changed Scope (S:C)**: This is a crucial factor in the high severity rating. The vulnerability could allow an attacker to break out of the containerized environment and affect the host system or other containers, effectively changing the security scope of the attack.

- **High Impact (C:H/I:H/A:H)**: Root access within the container provides attackers with maximum impact across all security properties:
  - **Confidentiality**: Full access to all data within the container and potentially host-mounted volumes
  - **Integrity**: Ability to modify any files, configurations, and application behavior
  - **Availability**: Capability to disrupt or crash containerized services

This combination of factors, particularly the scope change potential and high impacts, justifies the High severity rating of 8.8.

# Exploitation Scenarios
**Scenario 1: Container Escape via Kernel Vulnerability**
An attacker first exploits a remote code execution vulnerability in the Node.js web application. Because the container runs as root, the attacker can then leverage known kernel vulnerabilities to escape the container isolation. For example, they might exploit a vulnerability in the container runtime to gain access to the host system. Once on the host, they could access sensitive data, move laterally through the network, or establish persistence.

```bash
# Example of how an attacker might exploit root access after gaining RCE
# Check if running as root
id

# Exploit a kernel vulnerability (simplified example)
./kernel-exploit

# Check if container escape was successful by accessing host-specific resources
cat /proc/1/environ
ls -la /host_mnt/  # If successful, might see host filesystem

```

**Scenario 2: Access to Sensitive Host-Mounted Volumes**
Many containerized deployments mount volumes from the host for configuration, data persistence, or logging. An attacker who gains execution in a root-running container can access all contents of these mounted volumes, regardless of file permissions. This could expose sensitive configuration files, credentials, or business data.

```bash
# After gaining RCE in the container running as root
# Explore mounted volumes for sensitive information
find / -type d -name "*volume*" -o -name "*mount*" | xargs ls -la

# Read sensitive configuration possibly containing credentials
cat /mnt/config/database.yml
cat /mnt/secrets/api_keys.json

```

**Scenario 3: Docker Socket Exploitation**
If the Docker socket is mounted in the container (a common but dangerous practice), an attacker with root access can use it to control the Docker daemon on the host. This allows creating new privileged containers, accessing any volume on the host, or even executing commands directly on the host system.

```bash
# Check if Docker socket is mounted
ls -la /var/run/docker.sock

# If socket is available, use it to create a new privileged container that mounts the host filesystem
docker run -v /:/host_root -it ubuntu chroot /host_root bash

```

**Scenario 4: Credential Theft and Lateral Movement**
Containers often contain environment variables, configuration files, or mounted secrets with credentials for databases, APIs, or other services. With root access, an attacker can harvest these credentials and use them to access other systems in the infrastructure.

```bash
# Examine environment variables for secrets
printenv | grep -i key
printenv | grep -i secret
printenv | grep -i password

# Check common locations for credential files
find / -name "*.json" -o -name "*.yml" -o -name "*.key" | xargs grep -l "secret"

```

# Impact Analysis
**Business Impact:**
- **Data Breaches**: Unauthorized access to sensitive customer data, intellectual property, or business information could lead to significant financial and reputational damage.

- **Regulatory Compliance Violations**: Organizations handling personal data may face substantial penalties under regulations like GDPR, CCPA, or industry-specific frameworks if a container compromise leads to data exposure.

- **Service Disruption**: Attackers with root privileges can disrupt containerized services, causing downtime and affecting business operations and customer experience.

- **Lateral Movement Risk**: A compromised container running as root provides attackers with a stronger position to move laterally within the infrastructure, potentially leading to widespread compromise.

- **Incident Response Costs**: Addressing a container security breach requires significant resources for investigation, remediation, and potential system rebuilds.

**Technical Impact:**
- **Container Escape**: Root privileges significantly increase the likelihood of successful container escape, bridging the security boundary between the container and the host.

- **Host System Access**: If container isolation is bypassed, attackers may gain access to the underlying host OS, compromising the entire host and potentially other containers.

- **Data Access and Modification**: Root privileges allow unrestricted access to all files within the container, including application data, logs, and potentially mounted volumes from the host.

- **Configuration Tampering**: Attackers can modify application configurations, insert backdoors, or change security settings to maintain persistence.

- **Credential Theft**: Access to environment variables, configuration files, and in-memory data that may contain credentials to other systems.

- **Resource Abuse**: The ability to consume excessive CPU, memory, or network resources, potentially affecting other containers or services on the same host.

- **Monitoring Evasion**: Root privileges enable attackers to tamper with logging mechanisms or delete evidence of intrusion, complicating detection and forensic analysis.

# Technical Details
The vulnerability exists because the Dockerfile used to build the Node.js web server image does not include a `USER` directive to specify a non-root user for running the container processes. In Docker, when no user is specified, containers run as `root` (UID 0) by default.

```dockerfile
# Vulnerable Dockerfile
FROM node:14
WORKPLACE /app
COPY package.json package-lock.json ./
RUN npm install
COPY . .
CMD ["node", "server.js"]

```

When a container runs with root privileges, several security implications arise:

1. **Excessive Permissions**: The root user within a container has maximum permissions to all resources within that container.

2. **Container Isolation Weakening**: While Docker provides isolation between containers and the host, this isolation is not perfect. Running as root increases the impact of any isolation vulnerabilities.

3. **Potential for Container Escape**: If an attacker exploits a vulnerability in the container runtime or kernel, root privileges make it more likely they can "escape" to the host system.

4. **Access to Host Resources**: If volumes are mounted from the host, a root user in the container can access these with the same permissions as the root user on the host.

The technical risk is compounded by several factors:

1. **CI/CD Pipeline Integration**: The vulnerability is systematic because it exists in the Docker image building process within the CI/CD pipeline, affecting all deployments.

2. **Microservice Architecture**: In a microservices environment, the compromise of one container can provide a foothold for attacking other services.

3. **Default Node.js Behavior**: Node.js applications don't require root privileges to run, but without explicit configuration, they inherit the container's root privileges unnecessarily.

4. **Docker Configuration Options**: The risk is especially high in environments where:
   - Host volumes are mounted into containers
   - The Docker socket is mounted into containers
   - Containers use host networking
   - AppArmor, SELinux, or other security mechanisms are disabled
   - Containers are run with additional capabilities or in privileged mode

When a Node.js application vulnerability (such as command injection, insecure deserialization, or remote code execution) is exploited in a container running as root, the attacker immediately gains root-level access within that container, creating a dangerous starting point for further attacks.

# Remediation Steps
## Add Non-Root USER Directive to Dockerfile

**Priority**: P0

Modify the Dockerfile to create and use a non-privileged user for running the application:

```dockerfile
FROM node:14

WORKDIR /app

# Create a non-root user to run the application
RUN groupadd -r nodejs && useradd -r -g nodejs -m -d /home/nodejs -s /sbin/nologin -c "NodeJS user" nodejs

COPY package.json package-lock.json ./
RUN npm install
COPY . .

# Set proper ownership of application files
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

CMD ["node", "server.js"]

```

This change creates a dedicated user with minimal privileges specifically for running the Node.js application. The user has no login shell and belongs to a specific group, following the principle of least privilege. Additionally, the ownership of application files is explicitly set to this user to ensure proper access permissions.

Alternatively, for a simpler approach if using the official Node.js image, you can use the built-in non-root user:

```dockerfile
FROM node:14

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install
COPY . .

# Use the node user (non-root) that comes with the official image
USER node

CMD ["node", "server.js"]

```

This change should be implemented immediately across all affected Dockerfiles and container images.
## Implement Container Security Scanning in CI/CD Pipeline

**Priority**: P1

Integrate automated container security scanning into your CI/CD pipeline to prevent privileged containers and other security issues from reaching production:

```yaml
# Example GitLab CI/CD pipeline stage for container scanning
container_scanning:
  stage: security
  image: docker:stable
  services:
    - docker:dind
  variables:
    DOCKER_DRIVER: overlay2
  script:
    # Build the container image
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    
    # Run Trivy scanner against the built image
    - docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL --exit-code 1 $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    
    # Run Docker Bench Security to check for security best practices
    - docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker/docker-bench-security
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  allow_failure: false

```

This implementation:

1. Adds a dedicated security stage to your CI/CD pipeline
2. Uses Trivy to scan for vulnerabilities in the container image
3. Employs Docker Bench Security to check for Docker security best practices
4. Fails the pipeline if HIGH or CRITICAL issues are detected

Additionally, implement policy enforcement to reject containers running as root:

```yaml
# Example OPA/Conftest policy to reject containers running as root
package main

deny[msg] {
  input.user == "root"
  msg = "Container must not run as root user"
}

deny[msg] {
  not input.user
  msg = "USER instruction must be specified in Dockerfile"
}

```

Integrate this policy check into your pipeline to ensure all containers comply with the least privilege principle before deployment.


# References
* CWE-269 | [Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
* CWE-272 | [Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* CWE-250 | [Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
