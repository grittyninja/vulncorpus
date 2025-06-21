# Hardcoded AWS Credentials in Public Git Repository

# Vulnerability Case
During our routine review of Acme Corp's public Git repositories using a dedicated secrets scanning tool, we discovered hardcoded AWS credentials embedded within a configuration file. The analysis revealed an AWS Secret Access Key inadvertently committed alongside code for an AWS Lambda function written in Python using the boto3 library. The secret was detected using pattern-matching algorithms tuned for AWS credential formats, which flagged the exposed key in the file history. The presence of this key suggests potential unauthorized access to the company's cloud resources if leveraged by an attacker.

```python
# config.py - part of an AWS Lambda function using boto3
AWS_ACCESS_KEY_ID = "AKIAEXAMPLEKEY12345"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def initialize_client():
    import boto3
    # Vulnerable pattern: Using hardcoded credentials
    client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name="us-west-2",
    )
    return client

if __name__ == "__main__":
    s3_client = initialize_client()
    print("AWS client configured with hardcoded credentials")
```

The exposed AWS secret key, typically used in conjunction with AWS services like S3 and Lambda, could be exploited by attackers to impersonate the legitimate AWS user. By leveraging the exposed credentials, adversaries may perform unauthorized API calls, enumerate resources, exfiltrate sensitive data, or even provision additional malicious infrastructures. The potential business impact includes unauthorized cloud resource manipulation, leading to service disruptions, data breaches, and significant financial liabilities due to misuse of cloud services.


context: generic.secrets.security.detected-aws-secret-access-key.detected-aws-secret-access-key AWS Secret Access Key detected

# Vulnerability Breakdown
This vulnerability involves hardcoded AWS credentials (Access Key ID and Secret Access Key) exposed in a public Git repository, creating a significant security risk.

1. **Key vulnerability elements**:
   - AWS credentials directly embedded in source code (config.py)
   - Credentials committed to a publicly accessible Git repository
   - Exposing both AWS Access Key ID and Secret Access Key
   - Credentials used with boto3 for AWS service authentication
   - Discovered during routine secrets scanning of public repositories

2. **Potential attack vectors**:
   - Direct authentication to AWS services using the exposed credentials
   - Unauthorized access to S3 buckets (specified in the code)
   - Potential access to other AWS services depending on the IAM permissions associated with the credentials
   - Historical access through Git commit history even after credentials are removed

3. **Severity assessment**:
   - The credentials provide direct authentication to AWS cloud infrastructure
   - Access could enable data theft, resource manipulation, or service disruption
   - Exposure in a public repository makes exploitation trivial
   - No special access or skills required to exploit
   - Impact extends beyond the application to cloud infrastructure (changed scope)

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A critical security vulnerability has been identified in Acme Corp's codebase, where AWS credentials (Access Key ID and Secret Access Key) were hardcoded directly in a Python configuration file and committed to a public Git repository. The exposure was discovered during a routine secrets scanning operation targeting public repositories.

```python
# config.py - part of an AWS Lambda function using boto3
AWS_ACCESS_KEY_ID = "AKIAEXAMPLEKEY12345"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
def initialize_client():
    import boto3
    # Vulnerable pattern: Using hardcoded credentials
    client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name="us-west-2",
    )
    return client

```

This vulnerability provides attackers with direct access to AWS services (specifically S3 as shown in the code) using valid authentication credentials. The impact is severe as these credentials could be used to access sensitive data, manipulate resources, or disrupt services within the AWS account. Furthermore, even if the credentials are later removed from the current version of the repository, they remain accessible in the Git history, potentially leading to ongoing unauthorized access.

# CVSS
**Score**: 10.0 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H \
**Severity**: Critical

This vulnerability receives a Critical severity rating (CVSS score: 10.0) based on the following factors:

- **Network Attack Vector (AV:N)**: The credentials are exposed in a public Git repository that can be accessed by anyone with an internet connection.

- **Low Attack Complexity (AC:L)**: Exploiting the vulnerability is trivial and requires no special conditions or preparation. An attacker simply needs to find and use the exposed credentials.

- **No Privileges Required (PR:N)**: No authentication or privileges are needed to access the public repository and obtain the credentials.

- **No User Interaction Required (UI:N)**: Exploitation can be performed without any involvement from a legitimate user.

- **Changed Scope (S:C)**: The vulnerability in one security authority (the Git repository) affects resources in another security authority (the AWS cloud infrastructure).

- **High Confidentiality Impact (C:H)**: The credentials potentially allow full access to data stored in S3 buckets and possibly other AWS services, depending on the IAM permissions associated with the credentials.

- **High Integrity Impact (I:H)**: The credentials would allow an attacker to modify or delete objects in S3 buckets and potentially other resources.

- **High Availability Impact (A:H)**: An attacker could delete critical resources or exhaust resource quotas, disrupting business operations.

The maximum CVSS score of 10.0 reflects the severe, easily exploitable nature of this vulnerability and the significant potential impact across all security dimensions.

# Exploitation Scenarios
**Scenario 1: Data Exfiltration**
An attacker discovers the hardcoded AWS credentials while scanning public GitHub repositories for secrets. Using the credentials, they connect to the AWS S3 service in the us-west-2 region and list all accessible buckets. After identifying buckets containing sensitive data (customer information, intellectual property, configuration files), they download the contents using standard AWS CLI commands:

```bash
aws configure set aws_access_key_id AKIAEXAMPLEKEY12345
aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws configure set region us-west-2
aws s3 ls
aws s3 sync s3://acme-customer-data ./stolen-data

```

**Scenario 2: Infrastructure Abuse**
An attacker uses the exposed credentials to spin up expensive AWS resources for cryptocurrency mining. They create EC2 instances with high-performance GPUs and configure them to mine cryptocurrency, with all costs billed to Acme Corp's account. This attack could go unnoticed until the monthly AWS bill shows unexpected charges:

```bash
aws ec2 run-instances --image-id ami-gpu-optimized --instance-type p3.16xlarge --count 10

```

**Scenario 3: Resource Destruction and Ransomware**
An attacker uses the credentials to identify critical business data in S3 buckets. They first create copies of the data, then delete the original buckets, and leave a ransom note demanding payment for the return of the data:

```bash
# Copy data first
aws s3 sync s3://acme-critical-data ./stolen-backup

# Delete the original data
aws s3 rb s3://acme-critical-data --force

# Create a new bucket with a ransom note
aws s3 mb s3://acme-ransom-note
echo "Your data has been deleted. Contact ransomware@malicious.example for recovery instructions" > ransom.txt
aws s3 cp ransom.txt s3://acme-ransom-note/

```

**Scenario 4: Persistent Access**
A sophisticated attacker uses the initial credentials to create a new IAM user with programmatic access and administrative permissions, ensuring they maintain access even if the original compromised credentials are discovered and revoked:

```bash
aws iam create-user --user-name support-backup
aws iam attach-user-policy --user-name support-backup --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name support-backup

```

# Impact Analysis
**Business Impact:**
- **Financial Loss**: Unauthorized usage of AWS resources could lead to significant unexpected charges, especially if attackers deploy costly compute resources for cryptocurrency mining or other resource-intensive operations.

- **Data Breach**: Exposure of sensitive customer data, intellectual property, or business information stored in S3 buckets could lead to regulatory penalties, particularly under frameworks like GDPR, CCPA, or industry-specific regulations.

- **Operational Disruption**: Deletion or modification of critical resources could disrupt business operations, leading to downtime, lost productivity, and potential revenue impacts.

- **Reputational Damage**: Public disclosure of a data breach resulting from this vulnerability could damage customer trust and brand reputation, potentially leading to customer churn.

- **Remediation Costs**: Resources required to investigate the breach, restore data, implement proper security controls, and potentially provide credit monitoring for affected customers represent significant unplanned costs.

- **Legal Liability**: Potential lawsuits from affected parties whose data was exposed due to negligent security practices.

**Technical Impact:**
- **Unauthorized Data Access**: Complete read access to all data in S3 buckets, potentially including sensitive configurations, customer data, backups, and application files.

- **Data Integrity Violations**: Modification of data within S3 buckets, potentially corrupting application data, configurations, or other critical information.

- **Resource Manipulation**: Creation, modification, or deletion of AWS resources, depending on the IAM permissions associated with the exposed credentials.

- **Lateral Movement**: Use of the initial access to gain broader permissions within the AWS account, potentially compromising additional services beyond S3.

- **Persistent Access**: Difficulty in ensuring that all unauthorized access has been eliminated, as attackers may have created additional credentials or backdoors.

- **Regulatory Non-Compliance**: Failure to protect access credentials represents a violation of multiple security frameworks and best practices, potentially leading to compliance issues.

# Technical Details
The vulnerability stems from poor secrets management practices in the application's codebase. Specifically, AWS credentials are hardcoded directly in a Python configuration file that was committed to a public Git repository.

```python
# config.py - part of an AWS Lambda function using boto3
AWS_ACCESS_KEY_ID = "AKIAEXAMPLEKEY12345"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def initialize_client():
    import boto3
    # Vulnerable pattern: Using hardcoded credentials
    client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name="us-west-2",
    )
    return client

```

**Key Technical Issues:**

1. **Hardcoded Credentials**: AWS credentials are directly embedded in code rather than being retrieved from a secure source at runtime.

2. **Git Exposure**: The credentials were committed to a Git repository, making them part of the version history. Even if removed in later commits, they remain accessible in the repository's history.

3. **Public Accessibility**: The repository is publicly accessible, allowing anyone to discover these credentials.

4. **AWS Access Key Format**: The credentials follow the standard AWS format (Access Key IDs begin with "AKIA"), making them easily identifiable by automated scanning tools.

5. **Direct AWS Resource Access**: The code directly initializes an S3 client with these credentials, confirming they are valid and used to access AWS resources.

**Exposure Detection:**
The vulnerability was discovered during routine scanning of public Git repositories using a specialized secrets detection tool. These tools typically use pattern matching and entropy analysis to identify potential secrets in code. AWS credentials have a distinctive format and structure, making them relatively easy to detect with automated tools.

**AWS Context:**
The AWS Access Key ID and Secret Access Key together form a long-term credential pair that provides programmatic access to AWS services. These credentials are equivalent to a username and password for AWS API access and should be protected with the same level of security. When presented to AWS services, these credentials allow actions based on the IAM permissions assigned to the associated IAM user or role.

**Risk Amplification Factors:**

1. **Long-Term Validity**: Unlike temporary credentials, these long-term credentials do not automatically expire and remain valid until explicitly revoked.

2. **Potential Wide Scope**: Depending on the IAM permissions assigned to these credentials, they could have broad access to multiple AWS services beyond just S3.

3. **Git Persistence**: Even after credentials are rotated, old versions remain accessible in Git history unless repository history is rewritten (a complex and potentially disruptive process).

# Remediation Steps
## Immediate Credential Rotation and Exposure Mitigation

**Priority**: P0

1. **Revoke Exposed Credentials Immediately**:
   - Log into the AWS Management Console
   - Navigate to IAM → Users → [user associated with exposed key]
   - Delete or deactivate the exposed access key
   - Create new credentials if needed

   ```bash
   # CLI alternative
   aws iam delete-access-key --access-key-id AKIAEXAMPLEKEY12345 --user-name [username]
   
```

2. **Assess Damage and Review AWS Logs**:
   - Check CloudTrail logs for any activity using the exposed credentials
   - Review S3 access logs for unauthorized downloads
   - Scan for any new or unexpected IAM users, roles, or policies
   - Look for unauthorized EC2 instances or other resources

   ```bash
   # Example command to check CloudTrail events related to the exposed key
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAEXAMPLEKEY12345
   
```

3. **Remove Credentials from Git History**:
   - Use tools like BFG Repo-Cleaner or git-filter-branch to purge credentials
   - Force-push the cleaned repository
   - Consider making the repository private until cleaned

   ```bash
   # Example using BFG to remove credentials
   bfg --replace-text credentials.txt my-repo.git
   cd my-repo.git
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive
   git push --force
   
```

4. **Notify Security Team**:
   - Report the incident to the security team
   - Document the exposure timeline and affected resources
   - Follow company incident response procedures
## Implement Proper AWS Credential Management

**Priority**: P1

1. **Use Environment Variables for Local Development**:
   - Remove hardcoded credentials from code
   - Use environment variables for local development

   ```python
   # config.py - Updated version
   import os
   
   def initialize_client():
       import boto3
       # Use environment variables or boto3's credential discovery
       client = boto3.client(
           "s3",
           region_name="us-west-2"
       )
       return client
   
```

2. **Utilize AWS IAM Roles for Lambda Functions**:
   - Configure Lambda with an appropriate IAM role
   - Remove any direct credential handling

   ```python
   # No credentials needed when using IAM roles
   def initialize_client():
       import boto3
       # AWS Lambda automatically provides credentials via the assigned role
       client = boto3.client("s3", region_name="us-west-2")
       return client
   
```

3. **Implement AWS Secrets Manager for Application Secrets**:
   - Store any required secrets in AWS Secrets Manager
   - Retrieve secrets programmatically at runtime

   ```python
   def initialize_client_with_secrets():
       import boto3
       import json
       
       # Get secrets from AWS Secrets Manager
       secrets_client = boto3.client('secretsmanager')
       secret_response = secrets_client.get_secret_value(SecretId='MyAppSecrets')
       secrets = json.loads(secret_response['SecretString'])
       
       # Use retrieved credentials if needed (typically not necessary with IAM roles)
       client = boto3.client(
           "s3",
           region_name="us-west-2"
       )
       return client
   
```

4. **Implement Git Pre-commit Hooks to Prevent Future Leaks**:
   - Install pre-commit hooks to scan for secrets before commits
   - Use tools like git-secrets or detect-secrets

   ```bash
   # Install git-secrets
   git clone https://github.com/awslabs/git-secrets.git
   cd git-secrets
   make install
   
   # Set up in your repository
   cd /path/to/your/repo
   git secrets --install
   git secrets --register-aws
   
```

5. **Set Up Secret Scanning in CI/CD Pipeline**:
   - Implement automated secret scanning in your CI/CD pipeline
   - Block builds/deployments if secrets are detected


# References
* CWE-798 | [Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
* CWE-200 | [Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
* AWS-SEC-03 | [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
