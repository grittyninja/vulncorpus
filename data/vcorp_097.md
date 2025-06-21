# Arbitrary Code Execution via Unsanitized eval() in AWS Lambda

# Vulnerability Case
During our penetration testing of Acme Corp's AWS Lambda functions configured with Node.js (14.x runtime), we discovered a critical vulnerability in a function that processes user input from an API Gateway event. The function dangerously passed unsanitized, external input directly into the JavaScript `eval()` function. This issue was identified during a comprehensive code review aimed at assessing the execution of dynamically evaluated content. The misuse of `eval()` creates an avenue for arbitrary code execution within the Lambda environment, putting the underlying AWS resources at risk of unauthorized access or manipulation.

```javascript
exports.handler = async (event) => {
  // Extracting user-supplied code from query parameters
  const userCode = event.queryStringParameters.code;
  
  // Security risk: Direct usage of eval() on external input
  const result = eval(userCode);
  
  return {
    statusCode: 200,
    body: JSON.stringify({ result }),
  };
};
```

The exploitation of this vulnerability relies on injecting malicious JavaScript code into the `code` parameter via an API Gateway request. By crafting input that includes harmful payloads, an attacker can execute arbitrary commands on the AWS Lambda execution environment. This not only jeopardizes the isolation boundaries provided by the Lambda runtime but may also enable lateral movement into other connected AWS services, leading to a significant business impact including data exfiltration, denial of service, or unauthorized modifications to critical infrastructure.


context: javascript.aws-lambda.security.tainted-eval.tainted-eval The `eval()` function evaluates JavaScript code represented as a string. Executing JavaScript from a string is an enormous security risk. It is far too easy for a bad actor to run arbitrary code when you use `eval()`. Ensure evaluated content is not definable by external sources.

# Vulnerability Breakdown
This vulnerability allows remote attackers to execute arbitrary JavaScript code within an AWS Lambda function due to direct use of the eval() function on user-controlled input from API Gateway.

1. **Key vulnerability elements**:
   - Direct use of eval() on unvalidated user input from queryStringParameters
   - Node.js (14.x) Lambda function exposed via API Gateway
   - No input sanitization or validation mechanisms
   - Lambda execution context potentially having access to AWS services

2. **Potential attack vectors**:
   - Crafting malicious JavaScript code payloads in the code parameter
   - API Gateway requests that inject JavaScript with harmful functionality
   - Exploiting Lambda's AWS service permissions for lateral movement
   - Accessing Lambda environment variables containing secrets

3. **Severity assessment**:
   - High confidentiality impact through potential access to environment variables and connected resources
   - High integrity impact through ability to modify data in connected services
   - High availability impact through potential service disruption
   - Network-based attack vector with low complexity
   - Changed scope as the vulnerability could affect other AWS services

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
A critical vulnerability has been discovered in an Acme Corp AWS Lambda function that processes user input from API Gateway events. The function directly passes unvalidated, user-supplied input to JavaScript's `eval()` function, enabling arbitrary code execution within the Lambda environment.

```javascript
exports.handler = async (event) => {
  // Extracting user-supplied code from query parameters
  const userCode = event.queryStringParameters.code;
  
  // Security risk: Direct usage of eval() on external input
  const result = eval(userCode);
  
  return {
    statusCode: 200,
    body: JSON.stringify({ result }),
  };
};

```

This implementation allows attackers to craft malicious API requests containing JavaScript code that will be executed within the Lambda's environment. Since AWS Lambda functions typically have IAM roles with permissions to access other AWS services, this vulnerability could enable lateral movement within the AWS account, potentially leading to data exfiltration, unauthorized modifications, or service disruption.

# CVSS
**Score**: 10.0 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H \
**Severity**: Critical

This vulnerability receives the maximum CVSS score of 10.0 (Critical) due to several factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely through API Gateway without requiring local access.
- **Low Attack Complexity (AC:L)**: Exploitation is straightforward, requiring only basic knowledge of JavaScript to craft malicious payloads.
- **No Privileges Required (PR:N)**: No authentication or authorization is needed to exploit the vulnerability, assuming the API Gateway endpoint is publicly accessible.
- **No User Interaction (UI:N)**: The vulnerability can be exploited without any actions from users.
- **Changed Scope (S:C)**: Successful exploitation affects not only the vulnerable Lambda function but potentially other AWS services and resources through the Lambda's IAM permissions.
- **High Impact on Confidentiality (C:H)**: Attackers can access sensitive information from environment variables, connected databases, or other AWS resources.
- **High Impact on Integrity (I:H)**: Attackers can modify data in connected services or resources available to the Lambda function.
- **High Impact on Availability (A:H)**: Attackers can disrupt the service by causing errors, consuming maximum execution time, or manipulating connected resources.

This combination of factors—easy remote exploitation with no privileges required, potential to break out of the Lambda environment, and high impact across all security properties—represents the most severe type of vulnerability.

# Exploitation Scenarios
**Scenario 1: Environment Variable Exfiltration**
An attacker sends a request to the API Gateway endpoint with the following payload in the `code` parameter:

```javascript
JSON.stringify(process.env)

```

This simple payload would return all environment variables configured for the Lambda function, potentially exposing sensitive information such as API keys, database credentials, or AWS configuration details that are stored as environment variables.

**Scenario 2: AWS Service Abuse**
The attacker executes a more sophisticated attack by injecting code that uses the AWS SDK (which is available by default in Lambda environments) to access other AWS services:

```javascript
const AWS = require('aws-sdk');
const s3 = new AWS.S3();
const result = await s3.listBuckets().promise();
return result;

```

This code would leverage the Lambda's IAM role to list all S3 buckets accessible to the function. The attacker could then extend this approach to read sensitive data from buckets, modify data, or access other AWS services like DynamoDB, SQS, or even other Lambda functions.

**Scenario 3: Persistent Backdoor Installation**
An attacker could attempt to establish persistence by creating new resources or modifying existing ones:

```javascript
const AWS = require('aws-sdk');
const lambda = new AWS.Lambda();
await lambda.createFunction({
  FunctionName: 'backdoor-function',
  Runtime: 'nodejs14.x',
  Role: process.env.AWS_LAMBDA_ROLE,
  Handler: 'index.handler',
  Code: {
    ZipFile: Buffer.from('exports.handler = async (event) => { /* malicious code */ }')
  }
}).promise();

```

This would create a new Lambda function with the same permissions as the vulnerable function, providing the attacker with persistent access to the AWS environment even if the original vulnerability is patched.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive data stored in AWS services accessible to the Lambda function
- Potential breach of customer information leading to regulatory violations (GDPR, CCPA, etc.)
- Financial losses from unauthorized usage of AWS resources or service disruption
- Remediation costs including security assessments, incident response, and service modifications
- Reputational damage if the breach becomes public or impacts customer-facing services
- Potential legal liability for data exposure or service unavailability

**Technical Impact:**
- Execution of arbitrary code within the Lambda runtime environment
- Access to and potential exfiltration of environment variables containing secrets and credentials
- Lateral movement to other AWS services through the Lambda's IAM role permissions
- Unauthorized data access in connected databases or storage services (e.g., DynamoDB, S3)
- Manipulation or deletion of data in accessible AWS resources
- Creation of unauthorized AWS resources for persistence or further attacks
- Potential denial of service by executing resource-intensive operations or exhausting concurrent execution limits
- Circumvention of application business logic and security controls

# Technical Details
The vulnerability stems from the direct use of JavaScript's `eval()` function on unsanitized user input, creating a classic code injection vulnerability. When the Lambda function is invoked through API Gateway, the `code` query parameter value is executed as JavaScript without any validation or sanitization.

```javascript
exports.handler = async (event) => {
  // Extracting user-supplied code from query parameters
  const userCode = event.queryStringParameters.code;
  
  // Security risk: Direct usage of eval() on external input
  const result = eval(userCode);
  
  return {
    statusCode: 200,
    body: JSON.stringify({ result }),
  };
};

```

**Why this is dangerous:**

1. **Execution Context**: JavaScript's `eval()` executes code with the same privileges as the rest of the Lambda function, giving it access to:
   - The `process` object with environment variables (`process.env`)
   - The Node.js `require` function to load modules
   - The global scope and all variables defined in the Lambda function
   - The AWS SDK that is available by default in Lambda environments

2. **Lambda's AWS Context**: AWS Lambda functions operate with an IAM role that grants them permissions to interact with other AWS services. By executing arbitrary code, an attacker can leverage these permissions to:
   - Access other AWS services (S3, DynamoDB, SQS, etc.)
   - Read from or write to connected databases
   - Invoke other Lambda functions
   - Create, modify, or delete AWS resources

3. **API Gateway Exposure**: Since the vulnerability is accessible through API Gateway, it can be exploited by anyone who can make HTTP requests to the endpoint. Without proper authentication, this effectively exposes the code execution capability to the public internet.

**Example exploitation flow:**

1. Attacker identifies the vulnerable API endpoint (e.g., `https://api.example.com/execute?code=...`)
2. Attacker crafts a payload containing malicious JavaScript code
3. The payload is URL-encoded and sent as the `code` parameter in an HTTP GET request
4. The Lambda function receives the request and extracts the `code` parameter
5. The function passes the code to `eval()`, executing it in the Lambda environment
6. The result of the execution is returned to the attacker in the HTTP response

**AWS Lambda's security context exacerbates the issue:**

- Lambda functions often have broad permissions to access various AWS services
- IAM roles for Lambda typically grant read/write access to specific resources
- Environment variables in Lambda commonly contain sensitive configuration details
- The ephemeral nature of Lambda makes some traditional detection methods less effective

# Remediation Steps
## Remove eval() Usage

**Priority**: P0

The most secure approach is to completely eliminate the use of `eval()` by implementing a predefined set of safe operations that users can invoke through controlled parameters:

```javascript
exports.handler = async (event) => {
  // Extract operation and parameters from query string
  const { operation, params } = event.queryStringParameters;
  
  // Define a map of allowed operations
  const operations = {
    add: (a, b) => Number(a) + Number(b),
    subtract: (a, b) => Number(a) - Number(b),
    multiply: (a, b) => Number(a) * Number(b),
    divide: (a, b) => Number(b) !== 0 ? Number(a) / Number(b) : null,
    // Add other safe operations as needed
  };
  
  // Verify the requested operation exists
  if (!operations[operation]) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Invalid operation' }),
    };
  }
  
  // Parse parameters and execute the operation
  const paramArray = JSON.parse(params || '[]');
  const result = operations[operation](...paramArray);
  
  return {
    statusCode: 200,
    body: JSON.stringify({ result }),
  };
};

```

This approach replaces arbitrary code execution with a controlled set of predefined functions, eliminating the vulnerability entirely. Users can only invoke operations that have been explicitly defined and implemented in a secure manner.
## Implement Sandboxing if Dynamic Execution is Required

**Priority**: P1

If there is a legitimate business need to execute user-provided code, implement a proper sandboxing solution:

```javascript
const vm = require('vm');

exports.handler = async (event) => {
  try {
    // Extract user code from query parameters
    const userCode = event.queryStringParameters.code;
    
    // Create a restricted sandbox context
    const sandbox = {
      // Provide only whitelisted objects and functions
      console: { log: console.log },
      // Add other safe objects or functions as needed
      // Do NOT provide process, require, or AWS SDK
    };
    
    // Set timeout to prevent infinite loops
    const vmContext = vm.createContext(sandbox);
    const script = new vm.Script(userCode);
    
    // Execute with timeout (e.g., 1000ms)
    const result = script.runInContext(vmContext, { timeout: 1000 });
    
    return {
      statusCode: 200,
      body: JSON.stringify({ result }),
    };
  } catch (error) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Execution error', message: error.message }),
    };
  }
};

```

This approach uses Node.js's `vm` module to create a restricted execution context with only whitelisted objects available. It also implements a timeout to prevent denial-of-service attacks through infinite loops. However, note that the `vm` module is not a perfect security boundary and should be combined with other security measures.


# References
* CWE-95 | [Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
