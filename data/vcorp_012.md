# NoSQL Injection in .NET Core gRPC Service

# Vulnerability Case
During our assessment of Acme Corp’s .NET Core gRPC service interfacing with MongoDB, we identified a critical NoSQL injection flaw. The issue was discovered during code review and dynamic analysis where the gRPC endpoint directly interpolated unsanitized user input into a MongoDB query filter. This design flaw allowed for the manipulation of query logic by embedding malicious payloads in the input parameter. The vulnerability was observed in a scenario where an attacker could inject special characters or MongoDB operators to alter the intended query behavior, thereby bypassing access controls. Exploitable manipulation of query parameters in this context could lead to unauthorized access or modification of sensitive data.


```csharp
using Grpc.Core;
using MongoDB.Bson;
using MongoDB.Driver;
using System.Threading.Tasks;

public class UserService : UserService.UserServiceBase
{
    private readonly IMongoCollection<BsonDocument> _users;

    public UserService(IMongoDatabase database)
    {
        _users = database.GetCollection<BsonDocument>("users");
    }

    public override async Task<UserResponse> GetUserInfo(UserRequest request, 
        ServerCallContext context)
    {
        // Vulnerable pattern: Directly concatenates unsanitized gRPC input into the query.
        var query = BsonDocument.Parse($"{{ 'username': '{request.Username}' }}");
        var userDoc = await _users.Find(query).FirstOrDefaultAsync();

        if (userDoc == null)
        {
            return new UserResponse { Found = false };
        }
        
        return new UserResponse 
        { 
            Found = true, 
            UserJson = userDoc.ToJson() 
        };
    }
}
```

The vulnerability stems from concatenating user-controlled input directly into a MongoDB query without proper sanitation or parameterization. An attacker can exploit this by injecting malicious payloads—such as operators like `"$ne": null`—to alter the query behavior, potentially causing it to return all documents or bypass application-level filters. This could lead to unauthorized disclosure of sensitive user data, data corruption, or deletion of records. In a real-world environment running on .NET Core (e.g., version 3.1 or later), gRPC, and MongoDB, such an exploit could compromise the confidentiality and integrity of critical business data, leading to severe regulatory, financial, and reputational consequences.

context: csharp.dotnet-core.nosqli.mongodb-taint-grpc.mongodb-taint-grpc Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

# Vulnerability Breakdown
This vulnerability involves a NoSQL injection flaw in Acme Corp's .NET Core gRPC service where user-controlled input is directly concatenated into MongoDB queries without proper sanitization.

1. **Key vulnerability elements**:
   - Direct string interpolation of unsanitized user input into MongoDB query
   - Use of `BsonDocument.Parse()` with dynamically constructed JSON
   - Lack of input validation or parameterization
   - Return of complete user document to client

2. **Potential attack vectors**:
   - Injection of MongoDB operators like `$ne`, `$gt`, `$where` to alter query logic
   - Authentication bypass by manipulating query conditions
   - Data exfiltration through carefully crafted queries
   - Potential for more advanced attacks like denial of service

3. **Severity assessment**:
   - High confidentiality impact due to unauthorized data access
   - High integrity impact from potential data modification
   - Low availability impact as service may continue functioning
   - Network-accessible attack vector
   - Low complexity exploitation requiring minimal skill

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): Low (L) 

# Description
A critical NoSQL injection vulnerability has been identified in Acme Corp's .NET Core gRPC service that interfaces with MongoDB. The vulnerability exists in the `GetUserInfo` method of the `UserService` class, where user-controlled input from a gRPC request is directly concatenated into a MongoDB query without proper sanitization or parameterization.

```csharp
var query = BsonDocument.Parse($"{{ 'username': '{request.Username}' }}");
var userDoc = await _users.Find(query).FirstOrDefaultAsync();

```

This insecure pattern allows attackers to inject MongoDB operators and manipulate the query's behavior, potentially bypassing authentication mechanisms, accessing unauthorized data, or modifying database records. For example, an attacker could submit input containing special characters or MongoDB-specific operators (like `$ne`, `$gt`, or `$where`) to alter the query's logic and retrieve information beyond their authorization level.

# CVSS
**Score**: 9.4 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L \
**Severity**: Critical

The Critical severity rating (9.4) is justified by multiple factors:

- **Network Attack Vector (AV:N)**: The vulnerability is in a gRPC service which is accessible over the network, allowing remote exploitation
- **Low Attack Complexity (AC:L)**: Exploitation requires minimal technical knowledge – simply crafting an input containing MongoDB operators
- **No Privileges Required (PR:N)**: The vulnerable endpoint appears to be accessible without authentication
- **No User Interaction (UI:N)**: Exploitation can be fully automated without requiring actions from any legitimate users
- **Unchanged Scope (S:U)**: The impact is contained within the vulnerable component (database accessed by the service)
- **High Confidentiality Impact (C:H)**: An attacker could potentially access all user records in the MongoDB collection
- **High Integrity Impact (I:H)**: An attacker could likely modify or delete database records through further injection techniques
- **Low Availability Impact (A:L)**: While service might experience degradation from malicious queries, complete denial of service is less likely

This combination results in a CVSS Base Score of 9.4, placing it firmly in the Critical range. The severity is particularly high because the vulnerability combines easy exploitation with potential access to all user data.

# Exploitation Scenarios
**Scenario 1: Authentication Bypass**
An attacker targeting the user login functionality provides a specially crafted username parameter to the gRPC call: `username[$ne]=nonexistent`. When processed, this becomes the MongoDB query `{ 'username': { '$ne': 'nonexistent' } }`, which matches any user whose username is not 'nonexistent'. This effectively bypasses authentication, allowing the attacker to gain access to the first user account in the collection, potentially an administrator account.

**Scenario 2: Data Exfiltration**
An attacker exploits the injection vulnerability to extract sensitive information from other fields in the user collection. By sending a request with the parameter `username[$gt]=a`, the attacker creates a query `{ 'username': { '$gt': 'a' } }` that returns all users with usernames greater than 'a' (virtually all users). This can be further refined for targeted data extraction, especially if the service returns the entire user document including sensitive fields such as email addresses, phone numbers, or hashed passwords.

**Scenario 3: Schema Mapping and Enumeration**
An attacker uses MongoDB operators to explore the database schema. By sending multiple crafted requests with the `$exists` operator (e.g., `username[$exists]=true, some_field[$exists]=true`), the attacker can determine which fields exist in the user documents. This information gathering phase enables more sophisticated attacks targeting specific fields for exploitation or data theft.

**Scenario 4: JavaScript Execution**
In more advanced scenarios where MongoDB is configured to allow JavaScript execution, an attacker might inject into the query using the `$where` operator: `username[$where]=function(){sleep(5000); return true;}`. This would execute a sleep command on the MongoDB server, causing a 5-second delay in the response. This technique allows attackers to perform timing attacks, server-side operations, or potentially execute more dangerous JavaScript functions if allowed by the MongoDB configuration.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer data, potentially resulting in identity theft or fraud
- Regulatory violations leading to significant financial penalties (e.g., GDPR fines of up to 4% of annual global turnover)
- Mandatory breach notifications to affected users, causing reputational damage
- Loss of customer trust and potential business relationships
- Legal liability for damages resulting from exposed personal information
- Costs associated with incident response, forensic investigation, and remediation

**Technical Impact:**
- Complete compromise of the user database, including potential access to all user records
- Ability to bypass authentication mechanisms, gaining unauthorized access to user accounts
- Potential to modify or delete database records, affecting data integrity
- Information disclosure of internal database structure, field names, and application logic
- Risk of privilege escalation if administrative accounts are compromised
- Potential for secondary attacks using harvested credentials or personal information
- Degraded performance if attackers execute resource-intensive queries against the database

# Technical Details
The vulnerability lies in the direct concatenation of unsanitized user input into a MongoDB query in the `GetUserInfo` method of the `UserService` class:

```csharp
public override async Task<UserResponse> GetUserInfo(UserRequest request, ServerCallContext context)
{
    // Vulnerable pattern: Directly concatenates unsanitized gRPC input into the query.
    var query = BsonDocument.Parse($"{{ 'username': '{request.Username}' }}");
    var userDoc = await _users.Find(query).FirstOrDefaultAsync();

    if (userDoc == null)
    {
        return new UserResponse { Found = false };
    }
    
    return new UserResponse 
    { 
        Found = true, 
        UserJson = userDoc.ToJson() 
    };
}

```

**Vulnerability Mechanics:**

1. **String Interpolation Issue**: The code uses C# string interpolation (`$"..."`) to insert the user-supplied username directly into a JSON string.

2. **MongoDB Query Parsing**: The string is then parsed into a `BsonDocument` using `BsonDocument.Parse()`, which evaluates the string as MongoDB query syntax.

3. **Special Characters Handling**: If the username contains special characters or MongoDB operators (e.g., `$ne`, `$gt`, `$or`), they're interpreted as part of the query structure rather than literal values.

4. **Query Execution**: The modified query is executed against the MongoDB database, potentially returning unintended results.

5. **Full Document Return**: The entire user document is converted to JSON and returned to the client, potentially exposing all user data fields.

**Example Exploitation:**

When a legitimate client provides a username like "john":
```json
{ "username": "john" }

```

But an attacker might provide:
```
john', '$ne': null }, {'x': 'x

```

Which results in the constructed query:
```json
{ 'username': 'john', '$ne': null }, {'x': 'x' }

```

This altered query structure can change the intended query logic, allowing for various manipulations including authentication bypass, data exfiltration, or record manipulation.

The vulnerable code also returns the complete user document as JSON (`userDoc.ToJson()`), which might include sensitive fields beyond just the username, further increasing the impact of a successful exploitation.

# Remediation Steps
## Use MongoDB's Parameterized Queries

**Priority**: P0

Replace string concatenation with MongoDB's parameterized query approach using filter builders:

```csharp
public override async Task<UserResponse> GetUserInfo(UserRequest request, ServerCallContext context)
{
    // Safe approach: Use filter builder with properly parameterized values
    var filter = Builders<BsonDocument>.Filter.Eq("username", request.Username);
    var userDoc = await _users.Find(filter).FirstOrDefaultAsync();

    if (userDoc == null)
    {
        return new UserResponse { Found = false };
    }
    
    return new UserResponse 
    { 
        Found = true, 
        UserJson = userDoc.ToJson() 
    };
}

```

This approach ensures that the input is properly treated as a value parameter rather than potentially interpretable query syntax. The MongoDB driver will automatically handle escaping and proper query construction.
## Implement Input Validation and Sanitization

**Priority**: P1

Add input validation to ensure the username parameter matches expected patterns before processing:

```csharp
public override async Task<UserResponse> GetUserInfo(UserRequest request, ServerCallContext context)
{
    // Validate input first
    if (string.IsNullOrEmpty(request.Username) || !IsValidUsername(request.Username))
    {
        return new UserResponse { Found = false, Error = "Invalid username format" };
    }

    // Use proper filter builder approach
    var filter = Builders<BsonDocument>.Filter.Eq("username", request.Username);
    var userDoc = await _users.Find(filter).FirstOrDefaultAsync();

    if (userDoc == null)
    {
        return new UserResponse { Found = false };
    }
    
    // Consider returning only necessary fields instead of the whole document
    return new UserResponse 
    { 
        Found = true,
        // Only return specific fields rather than the entire document
        UserJson = SanitizeUserDocument(userDoc).ToJson()
    };
}

private bool IsValidUsername(string username)
{
    // Username should only contain alphanumeric characters and limited symbols
    // Adjust regex pattern according to your username requirements
    return System.Text.RegularExpressions.Regex.IsMatch(
        username, 
        "^[a-zA-Z0-9_.-]{3,30}$"
    );
}

private BsonDocument SanitizeUserDocument(BsonDocument doc)
{
    // Create a new document with only the fields that should be exposed
    var sanitized = new BsonDocument();
    
    // Only copy allowed fields
    if (doc.Contains("username")) sanitized["username"] = doc["username"];
    if (doc.Contains("displayName")) sanitized["displayName"] = doc["displayName"];
    // Add other fields that are safe to expose
    
    return sanitized;
}

```

This approach adds multiple layers of security:
1. Validates input format before processing
2. Uses parameterized queries
3. Limits data returned to the client to only necessary fields


# References
* CWE-89 | [Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-943 | [Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
