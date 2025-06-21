# XPath Injection in gRPC Service

# Vulnerability Case
During the review of Acme Corp's .NET Core gRPC services, we discovered an XPath injection vulnerability in the dynamic construction of XPath queries that directly incorporate user-controlled input. The issue was identified while analyzing service logs and the gRPC method implementations where unsanitized values were concatenated into XPath expressions. An attacker could manipulate the input to alter the query logic, potentially exposing sensitive data stored in XML documents. This vulnerability could allow unauthorized access to critical user information, thus elevating the risk of data breaches and regulatory non-compliance.

```csharp
using System;
using System.Threading.Tasks;
using System.Xml;
using Grpc.Core;

namespace Acme.Grpc
{
    public class UserDataService : UserData.UserDataBase
    {
        public override Task<UserResponse> GetUserDetails(
            UserRequest request, ServerCallContext context)
        {
            // Vulnerable: Dynamic XPath query built with unsanitized user input.
            var xmlDoc = new XmlDocument();
            xmlDoc.Load("UserData.xml");

            // Direct interpolation of user-supplied input into the query
            string xpathQuery = $"/Users/User[@id='{request.UserId}']";

            // XPath injection risk: Malicious input in 'UserId' may alter query behavior
            XmlNode userNode = xmlDoc.SelectSingleNode(xpathQuery);
            var response = new UserResponse();

            if (userNode != null)
            {
                // Extraction of potentially sensitive information without additional checks
                response.Email = userNode["Email"]?.InnerText;
                response.Name = userNode["Name"]?.InnerText;
            }

            return Task.FromResult(response);
        }
    }
}
```

The vulnerability arises from constructing the XPath query using direct string interpolation without proper sanitization, allowing an attacker to inject additional XPath syntax. Exploitation could occur if an adversary crafts an input such as `' or '1'='1` to bypass intended query filters and retrieve all nodes in the XML document. In a real-world scenario, this could lead to unauthorized disclosure of sensitive user data, potentially resulting in regulatory penalties, competitive disadvantage, and damage to the organization's reputation.

context: csharp.dotnet-core.xpath-injection.xpath-taint-grpc.xpath-taint-grpc XPath queries are constructed dynamically on user-controlled input. This could lead to XPath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Thoroughly sanitize user input or use parameterized XPath queries if you can.

# Vulnerability Breakdown
This vulnerability involves the unsafe construction of XPath queries by directly embedding user-controlled input without sanitization in a .NET Core gRPC service.

1. **Key vulnerability elements**:
   - Direct string interpolation of untrusted user input into XPath queries
   - No input validation or sanitization of the `UserId` parameter
   - No use of parameterized XPath queries or safe XML APIs
   - Potential exposure of sensitive user information from XML documents
   - Implementation in a gRPC service that may be publicly accessible

2. **Potential attack vectors**:
   - Injecting XPath syntax like `' or '1'='1` to bypass filtering and retrieve all user records
   - Using more complex XPath expressions to extract specific information from the XML document
   - Exploiting the vulnerability to map the structure of the XML document for further attacks
   - Chaining with other vulnerabilities to escalate privileges or access additional resources

3. **Severity assessment**:
   - High confidentiality impact due to potential exposure of all user data
   - Network-based attack vector allowing remote exploitation
   - Low complexity to exploit with basic XPath knowledge
   - No privileges required to execute the attack
   - No user interaction needed for exploitation

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

# Description
An XPath injection vulnerability exists in Acme Corp's .NET Core gRPC service, specifically in the `UserDataService.GetUserDetails` method. The vulnerability occurs because the application constructs XPath queries by directly concatenating untrusted user input (`request.UserId`) into the query string without proper validation or sanitization.

```csharp
string xpathQuery = $"/Users/User[@id='{request.UserId}']"; // Vulnerable line
XmlNode userNode = xmlDoc.SelectSingleNode(xpathQuery);

```

This insecure implementation allows attackers to inject malicious XPath syntax that can alter the intended query logic. By crafting special inputs that contain XPath operators and syntax, an attacker could bypass filtering mechanisms and potentially access unauthorized data within the XML document, leading to significant data breaches and exposure of sensitive user information.

# CVSS
**Score**: 7.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: High

The High severity rating (7.5) is justified by the following factors:

- **Network attack vector (AV:N)**: The vulnerability exists in a gRPC service that can be accessed remotely across networks, allowing attackers to exploit it without requiring local access to the target system.

- **Low attack complexity (AC:L)**: Exploiting this vulnerability is straightforward and doesn't require advanced skills or special conditions. Basic knowledge of XPath injection techniques is sufficient.

- **No privileges required (PR:N)**: The vulnerable endpoint doesn't appear to require authentication or special privileges to access, making it exploitable by unauthenticated attackers.

- **No user interaction (UI:N)**: The vulnerability can be exploited without requiring any actions from legitimate users of the system.

- **Unchanged scope (S:U)**: The impact is limited to the vulnerable component itself (the XML data access functionality), without affecting other components.

- **High confidentiality impact (C:H)**: Successful exploitation could lead to unauthorized access to all user data stored in the XML document, potentially exposing sensitive personal information.

- **No integrity impact (I:N)**: Based on the code provided, the vulnerability appears to only allow read access to data without the ability to modify it.

- **No availability impact (A:N)**: The vulnerability doesn't affect the availability of the service or the underlying system.

# Exploitation Scenarios
**Scenario 1: Data Extraction Attack**
An attacker sends a gRPC request to the GetUserDetails method with a crafted UserId value such as `' or '1'='1`. This transforms the XPath query to `/Users/User[@id='' or '1'='1']` which will match ALL User nodes in the XML document, not just the specific user requested. As a result, the attacker receives the details of the first user in the document. By sending multiple requests with slight variations, the attacker can enumerate all users in the system.

**Scenario 2: Targeted Data Extraction**
An attacker uses more sophisticated XPath syntax to extract specific information, for example using UserId with value: `'] | /Users/User[contains(PrivateData,'credit')`. This creates an XPath query that specifically targets users with credit information in their private data. The attacker can continue refining their queries to extract increasingly sensitive information.

**Scenario 3: Blind XPath Injection**
If the gRPC service doesn't return full user details but only confirms if a user exists, an attacker can still exploit this using blind XPath injection techniques. The attacker sends a series of requests with payloads like `' and substring(name(/*[1]),1,1)='U` and analyzes the success/failure responses to determine the structure of the XML document element by element. This technique allows the attacker to map out the entire XML structure and eventually extract sensitive data, even without direct visibility to the full records.

# Impact Analysis
**Business Impact:**
- Unauthorized disclosure of sensitive user information stored in XML documents
- Potential regulatory violations (GDPR, CCPA, etc.) if personal data is exposed
- Financial penalties from regulatory bodies for inadequate security controls
- Damage to company reputation and loss of customer trust
- Possible litigation from affected users if their data is compromised
- Competitive disadvantage if proprietary data is exposed to competitors

**Technical Impact:**
- Complete exposure of all user data stored in the XML document
- Information disclosure revealing internal data structures and application logic
- Potential for extraction of credentials or tokens that could be used in secondary attacks
- Insight into the application's backend structure that could enable more targeted attacks
- Unauthorized access to restricted data that should only be accessible to specific users
- Bypassing of data access controls meant to enforce proper authorization

# Technical Details
The vulnerability exists in the dynamic construction of XPath queries within the `GetUserDetails` method of the `UserDataService` class. The root cause is the direct interpolation of user-controlled input into an XPath expression string without any sanitization or parameterization.

```csharp
// Vulnerable code
string xpathQuery = $"/Users/User[@id='{request.UserId}']"; // Direct string interpolation
XmlNode userNode = xmlDoc.SelectSingleNode(xpathQuery);

```

**XPath Injection Mechanics:**

XPath is a query language for selecting nodes from XML documents. When user input is directly incorporated into XPath queries without proper sanitization, attackers can manipulate the query's logic by injecting XPath syntax.

For example, if an attacker provides this input for `UserId`:
```
' or '1'='1

```

The resulting XPath query becomes:
```
/Users/User[@id='' or '1'='1']

```

This modified query will match ANY User node (because '1'='1' is always true), effectively bypassing the intended filtering by specific user ID.

More advanced attacks could use XPath functions and operators to extract specific information:

- Using boolean logic: `' or contains(//User/CreditCardNumber, '4')='true`
- Using the pipe operator for unions: `'] | //User[position()=2`
- Using position functions: `'] | //User[position()=2]/Password[1`

The vulnerability is particularly concerning in gRPC services because:

1. gRPC provides strong typing and contract validation, leading developers to sometimes overlook input validation
2. The binary protocol may make it less obvious that injection attacks are possible
3. Automated security scanning tools may have less coverage for gRPC endpoints compared to REST APIs

In the provided code, once the XPath query is executed, sensitive data like email addresses and names is extracted from the XML and returned to the caller without any authorization checks beyond the initial user ID match (which can be bypassed through injection).

# Remediation Steps
## Use Parameterized XPath Queries

**Priority**: P0

Replace direct string interpolation with parameterized XPath queries to prevent injection attacks:

```csharp
public override Task<UserResponse> GetUserDetails(
    UserRequest request, ServerCallContext context)
{
    var xmlDoc = new XmlDocument();
    xmlDoc.Load("UserData.xml");
    
    // Create namespace manager if needed (for XML with namespaces)
    XmlNamespaceManager nsManager = new XmlNamespaceManager(xmlDoc.NameTable);
    
    // Create a parameterized XPath query with a variable
    string xpathQuery = "/Users/User[@id=$userId]"; 
    
    // Create an XsltArgumentList to hold parameters
    XsltArgumentList xsltArgs = new XsltArgumentList();
    xsltArgs.AddParam("userId", "", request.UserId);
    
    // Execute the query with parameters
    XPathNavigator navigator = xmlDoc.CreateNavigator();
    XPathExpression expr = navigator.Compile(xpathQuery);
    expr.SetContext(nsManager); // if using namespaces
    
    // Apply the parameters to the query
    XPathNodeIterator iterator = navigator.Select(expr, xsltArgs);
    
    var response = new UserResponse();
    
    if (iterator.MoveNext())
    {
        // Extract data safely from the current node
        XPathNavigator currentNode = iterator.Current;
        response.Email = currentNode.SelectSingleNode("Email")?.Value;
        response.Name = currentNode.SelectSingleNode("Name")?.Value;
    }
    
    return Task.FromResult(response);
}

```

This approach separates the XPath query structure from the parameter values, preventing injection attacks by handling the parameters in a way that preserves their literal meaning rather than interpreting them as part of the XPath syntax.
## Implement Input Validation and Sanitization

**Priority**: P1

Apply strict input validation and sanitization to ensure that user inputs match expected formats before using them in XPath queries:

```csharp
public override Task<UserResponse> GetUserDetails(
    UserRequest request, ServerCallContext context)
{
    // Validate user ID format using a whitelist approach
    if (string.IsNullOrEmpty(request.UserId) || !Regex.IsMatch(request.UserId, "^[a-zA-Z0-9_-]+$"))
    {
        throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID format"));
    }
    
    var xmlDoc = new XmlDocument();
    xmlDoc.Load("UserData.xml");
    
    // Even with validation, sanitize input by escaping single quotes
    string sanitizedUserId = request.UserId.Replace("'", "''");
    string xpathQuery = $"/Users/User[@id='{sanitizedUserId}']";
    
    XmlNode userNode = xmlDoc.SelectSingleNode(xpathQuery);
    var response = new UserResponse();
    
    if (userNode != null)
    {
        // Additional authorization check to ensure the user has access to this data
        if (!IsAuthorizedToViewUser(context.GetHttpContext().User, userNode))
        {
            throw new RpcException(new Status(StatusCode.PermissionDenied, "Not authorized to access this user"));
        }
        
        response.Email = userNode["Email"]?.InnerText;
        response.Name = userNode["Name"]?.InnerText;
    }
    
    return Task.FromResult(response);
}

private bool IsAuthorizedToViewUser(ClaimsPrincipal user, XmlNode userNode)
{
    // Implement proper authorization logic
    // Example: Check if the current user has permission to view the requested user
    string requestedUserId = userNode.Attributes["id"]?.Value;
    return user.HasClaim("ViewUser", requestedUserId) || user.IsInRole("Administrator");
}

```

This approach combines multiple defensive layers:
1. Strict input validation using a whitelist of allowed characters
2. Input sanitization as a backup defense
3. Additional authorization checks to enforce proper access control


# References
* CWE-643 | [Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-89 | [Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-94 | [Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
