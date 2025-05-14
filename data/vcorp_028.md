# Hardcoded AWS Credentials in Source Code

# Vulnerability Case
During a routine static code analysis of Acme Corp's internal microservices repository, our automated scanning tools flagged a hardcoded AWS Access Key ID embedded in a configuration file. The credential was directly committed in the source code instead of being secured via environment variables or a dedicated secrets management solution. Manual validation confirmed that the exposed AWS key matched a format consistent with genuine credentials, raising significant concerns about potential unauthorized cloud access. Such exposure could allow an adversary to leverage the key for unsanctioned API calls on AWS, increasing the risk of data compromise and unauthorized resource manipulation.

```python
import boto3

# Vulnerable code: Hardcoded AWS credentials
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"  # Sensitive credential exposed in source code
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Hardcoded secret key

# Establish an AWS S3 client using the hardcoded credentials
s3_client = boto3.client(
    "s3",
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
)

# List S3 buckets as an example of AWS API usage
response = s3_client.list_buckets()
print(response)
```

This example utilizes the AWS ecosystem, the Python programming language, and its Boto3 SDK to interact with AWS S3 services. The vulnerability was discovered during code reviews in a CI/CD pipeline running on a Linux environment with integrated static analysis.

Hardcoding AWS Access Key IDs in source code enables threat actors to potentially harvest these credentials via unauthorized repository access or code scanning tools. Attackers can exploit the exposed key to authenticate against AWS services—initiating API calls that may list, modify, or delete critical cloud resources. This exploitation could lead to severe business impacts including data breaches, operational disruption, unauthorized resource provisioning, and significant financial liabilities due to unexpected cloud consumption.


context: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.

# Vulnerability Breakdown
This vulnerability involves directly embedding AWS credentials (Access Key ID and Secret Access Key) in Python source code instead of using secure methods for credential management.

1. **Key vulnerability elements**:
   - AWS Access Key ID and Secret Access Key hardcoded directly in source code
   - Credentials stored in cleartext within a version-controlled repository
   - Boto3 SDK using these credentials to establish authenticated AWS connections
   - Access to potentially sensitive S3 resources through these credentials

2. **Potential attack vectors**:
   - Repository compromise or unauthorized access
   - Source code exfiltration during code reviews
   - CI/CD pipeline logs capturing the credentials
   - Insider threats with repository access
   - Code sharing or publishing that inadvertently includes credentials

3. **Severity assessment**:
   - High confidentiality impact due to potential access to sensitive S3 data
   - High integrity impact from possible unauthorized modification of cloud resources
   - High availability impact if attacker deletes or disrupts critical resources
   - Scope is changed as the vulnerability in source code affects AWS environment
   - Adjacent attack vector requiring some level of internal access

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

CVSS Vector: CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

# Description
A critical security vulnerability exists in Acme Corp's internal microservices repository where AWS credentials (both Access Key ID and Secret Access Key) are hardcoded directly in a Python source file. The code uses these embedded credentials to authenticate with AWS S3 services via the Boto3 SDK.

```python
# Vulnerable code snippet
import boto3

# Hardcoded AWS credentials
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"  
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

s3_client = boto3.client(
    "s3",
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
)

```

Storing credentials in source code violates fundamental security principles and AWS best practices. Anyone with access to the repository (including developers, CI/CD systems, and potential attackers who gain access) can extract these credentials and use them to access AWS resources with the same permissions as the hardcoded credentials. This could lead to data breaches, unauthorized resource modification, or service disruption.

# CVSS
**Score**: 9.0 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H \
**Severity**: Critical

The Critical severity rating (9.0) is justified by the significant potential impact of this vulnerability:

- **Adjacent Attack Vector (AV:A)**: The vulnerability requires access to the internal repository, limiting the initial attack surface to those with some form of internal access rather than any internet user.

- **Low Attack Complexity (AC:L)**: Once an attacker has access to the code, exploitation is straightforward - they simply extract and use the credentials. No special conditions or sophisticated techniques are needed.

- **Low Privileges Required (PR:L)**: An attacker needs some level of access to the repository, such as developer credentials or CI/CD pipeline access, representing a low privilege requirement rather than none.

- **No User Interaction (UI:N)**: Exploitation does not require any actions from users; the attacker can directly use the extracted credentials.

- **Changed Scope (S:C)**: This is a key factor in the high score. The vulnerability in the source code repository (one security authority) affects AWS resources (a different security authority), creating a scope change that amplifies the impact.

- **High Confidentiality, Integrity, and Availability Impact (C:H/I:H/A:H)**: With valid AWS credentials, an attacker could potentially:
  - Access sensitive data in S3 buckets (confidentiality)
  - Modify or corrupt AWS resources (integrity)
  - Delete critical resources or disrupt services (availability)

The combination of these factors, particularly the changed scope and high impact across all three security objectives, results in the Critical severity rating of 9.0.

# Exploitation Scenarios
**Scenario 1: Repository Access Exploitation**
A contractor with temporary access to the development environment or an employee with limited responsibilities gains access to the repository containing the hardcoded credentials. They extract the AWS keys and, after their engagement ends or outside working hours, use these credentials to access S3 buckets containing sensitive customer data. The attack remains undetected because the access appears legitimate to AWS logging systems, using valid credentials.

**Scenario 2: CI/CD Pipeline Compromise**
An attacker gains access to the CI/CD pipeline logs or build artifacts. During builds, the source code with hardcoded credentials is processed, and the credentials might appear in build logs or debugging output. The attacker extracts these credentials and uses them to provision expensive AWS resources for cryptocurrency mining, resulting in significant unexpected charges to the organization's AWS account.

**Scenario 3: Inadvertent Code Publication**
A developer extracts part of the codebase for use in a different project or to share as an example on a public forum like Stack Overflow or GitHub. Without realizing it, they include the file containing hardcoded credentials. Even after the post is edited or deleted, the credentials remain in the site's history or have been harvested by credential-scanning bots that continuously monitor public repositories and forums for exposed credentials.

**Scenario 4: Source Code Exfiltration via Security Tool**
A vulnerability in a code analysis tool used in the development environment allows an attacker to extract results from security scans. Since the static analysis tool flags the hardcoded credentials (as mentioned in the context), the attacker gains access to these credentials directly from the security tool's findings rather than needing access to the original source code.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to sensitive customer data stored in S3 buckets, leading to regulatory violations (GDPR, CCPA, etc.)
- Financial losses from unauthorized use of AWS resources (compute, storage, bandwidth)
- Costs associated with incident response, forensic investigation, and remediation
- Reputation damage and loss of customer trust if a breach occurs and becomes public
- Possible legal liabilities and fines related to inadequate protection of sensitive data
- Business disruption if critical AWS resources are modified or deleted
- Violation of contractual obligations with customers regarding data protection

**Technical Impact:**
- Complete compromise of the AWS account associated with the credentials
- Access to all S3 buckets and objects accessible to the compromised credentials
- Potential for lateral movement if the credentials have permissions beyond S3
- AWS resource tampering (creation, modification, deletion) within the permission scope
- Data exfiltration capabilities for any readable S3 content
- Injection of malicious content into writable S3 buckets
- Creation of unauthorized IAM users or roles for persistent access
- Potential access to other AWS services depending on the IAM permissions associated with the keys
- Difficulty attributing unauthorized actions as they appear legitimate in AWS logs

# Technical Details
The vulnerability stems from embedding static AWS credentials directly in source code rather than using secure credential management practices. The specific issues are:

```python
import boto3

# Hardcoded credentials exposed in source code
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"  
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Direct use of hardcoded credentials to authenticate
s3_client = boto3.client(
    "s3",
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
)

```

**Technical vulnerability details:**

1. **Credential format and verification:**
   - AWS Access Key IDs follow a specific pattern (typically starting with "AKIA" or "ASIA" followed by 16 characters)
   - The example shows a properly formatted key that would pass validation when used with AWS services
   - These are long-lived credentials that don't expire unless explicitly rotated

2. **Exposure vectors:**
   - Source code repositories (including historical commits)
   - Code review systems where reviewers can see the credentials
   - CI/CD pipelines where the code is processed
   - Backup systems that might store copies of the code
   - Developer workstations with local copies of the repository

3. **AWS authentication mechanism:**
   - The boto3 client accepts these credentials directly for authentication
   - No additional factors are required to use these credentials once obtained
   - The AWS API accepts these credentials without knowledge of how they were obtained

4. **Scope of potential access:**
   - The specific S3 client created can access any S3 bucket allowed by the IAM permissions associated with these credentials
   - The credentials might have permissions beyond S3 depending on the IAM configuration
   - The code example shows listing all buckets (`list_buckets()`), indicating broad S3 read access

5. **Technical risk factors:**
   - Credentials cannot be easily invalidated in repository history without rewriting git history
   - AWS logs show normal API calls when credentials are used, making detection challenging
   - The python script doesn't implement any additional security controls like IP restrictions

# Remediation Steps
## Immediate Credential Rotation

**Priority**: P0

Immediately rotate (replace) the exposed AWS credentials:

1. Create new AWS access keys in the AWS IAM console for the affected user
2. Update all legitimate systems to use the new credentials via a secure method
3. Deactivate the exposed credentials in AWS IAM console
4. After verifying no legitimate systems are broken, delete the exposed credentials
5. Audit AWS CloudTrail logs for any suspicious activity using the exposed credentials

This is the most urgent action as it prevents further use of the compromised credentials, even if they remain in source code temporarily while implementing more comprehensive solutions.
## Implement Environment Variables for Credentials

**Priority**: P1

Refactor the code to use environment variables instead of hardcoded credentials:

```python
import boto3
import os

# Get credentials from environment variables
aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

# Validate credentials exist
if not aws_access_key_id or not aws_secret_access_key:
    raise EnvironmentError("AWS credentials not found in environment variables")

# Create the S3 client using environment variables
s3_client = boto3.client(
    "s3",
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
)

```

Update your deployment process to set these environment variables securely:

- For local development: Use `.env` files that are excluded from git (add to `.gitignore`)
- For CI/CD pipelines: Use the secret/environment variable features of your CI/CD platform
- For containerized deployments: Pass environment variables through container orchestration
- For production: Use a secure method to inject environment variables at runtime
## Implement AWS SDK Default Credential Provider Chain

**Priority**: P1

Refactor the code to use AWS SDK's built-in credential provider chain instead of explicitly providing credentials:

```python
import boto3

# Create S3 client without explicit credentials
# The SDK will automatically check multiple locations for credentials
s3_client = boto3.client("s3")

# Optional verification that credentials were found
try:
    response = s3_client.list_buckets()
    print(f"Successfully authenticated. Found {len(response['Buckets'])} buckets.")
except Exception as e:
    print(f"Authentication failed: {e}")

```

With this approach, the AWS SDK will automatically look for credentials in this order:

1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
2. Shared credential file (~/.aws/credentials)
3. AWS IAM Role for EC2/ECS/Lambda if running in those environments
4. Web identity token for EKS

This method provides flexibility across different environments and follows AWS best practices.
## Implement AWS Secrets Manager or Parameter Store

**Priority**: P2

For a more robust solution, use AWS Secrets Manager or Systems Manager Parameter Store to securely store and retrieve credentials:

```python
import boto3
import json

# Create a session using the default credential provider chain
session = boto3.session.Session()

# Get the secret from AWS Secrets Manager
secrets_client = session.client(service_name="secretsmanager")
secret_name = "my-service/aws-credentials"

try:
    # Get the secret value
    get_secret_response = secrets_client.get_secret_value(SecretId=secret_name)
    secret = json.loads(get_secret_response["SecretString"])
    
    # Extract credentials from the secret
    aws_access_key_id = secret.get("access_key_id")
    aws_secret_access_key = secret.get("secret_access_key")
    
    # Create S3 client with retrieved credentials
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )
    
except Exception as e:
    print(f"Error retrieving credentials: {e}")

```

This approach provides several security benefits:
- Centralized credential management
- Automatic credential rotation capabilities
- Fine-grained access control to secrets
- Encryption at rest and in transit
- Audit trail of secret access
## Implement IAM Roles for Service Authentication

**Priority**: P2

The most secure approach for AWS services is to eliminate long-term credentials entirely and use IAM roles:

```python
import boto3

# No credentials specified - relies on IAM role attached to the instance/container
s3_client = boto3.client("s3")

# The code now uses temporary credentials automatically managed by AWS
response = s3_client.list_buckets()
print(response)

```

Implementation steps:

1. Create appropriate IAM roles with least-privilege permissions specific to your application needs
2. For EC2: Attach IAM roles to EC2 instances running your application
3. For ECS/EKS: Configure task or pod IAM roles
4. For Lambda: Define execution roles with appropriate permissions
5. For local development: Use AWS CLI's assume-role capabilities or role-based profiles

This is the most secure option because:
- No long-term credentials exist that could be compromised
- Temporary credentials are automatically rotated
- Credentials never appear in code, configuration, or environment variables
- Fine-grained access control with least privilege principle
- Simplified credential management


# References
* CWE-798 | [Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
* CWE-312 | [Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
* A09:2021 | [Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
* AWS-IAM-KEYS-2 | [AWS Foundational Security Best Practices: IAM.4 - IAM root user access key should not exist](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html)
