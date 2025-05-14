# NoSQL Injection in Go Gin API with MongoDB

# Vulnerability Case
During our assessment of Acme Corp's user management API—built using the Go Gin framework with a MongoDB backend—we identified that untrusted query parameters are directly incorporated into database queries without proper sanitization. This vulnerability was uncovered during routine penetration testing when manipulated HTTP GET requests to the `/user` endpoint returned unexpected and excessive data, indicating potential NoSQL injection. The endpoint directly interpolates user-controlled input into the query filter, enabling attackers to inject MongoDB operators and alter query logic. In a realistic scenario, this could allow an attacker to bypass intended filtering and retrieve sensitive user records, posing severe risks to data confidentiality.  

```go  
package main  

import (  
  "context"  
  "net/http"  

  "github.com/gin-gonic/gin"  
  "go.mongodb.org/mongo-driver/mongo"  
  "go.mongodb.org/mongo-driver/mongo/options"  
)  

func main() {  
  r := gin.Default()  
  client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))  
  if err != nil {  
    panic(err)  
  }  
  collection := client.Database("acme").Collection("users")  

  r.GET("/user", func(c *gin.Context) {  
    email := c.Query("email")  
    // Vulnerable pattern: directly injecting untrusted input into the query filter  
    filter := map[string]interface{}{"email": email}  

    var user map[string]interface{}  
    if err := collection.FindOne(context.Background(), filter).Decode(&user); err != nil {  
      c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})  
      return  
    }  
    c.JSON(http.StatusOK, user)  
  })  

  r.Run(":8080")  
}  
```  

The vulnerability arises from constructing a MongoDB query using user-supplied data without validation, exposing the service to NoSQL injection. An attacker might supply a crafted payload—for example, `{"email": {"$ne": ""}}`—which would subvert the intended filtering logic and potentially return all user records. Exploitation could lead to unauthorized data exfiltration, but the provided code sample does not demonstrate write operation vulnerabilities (e.g., modification or deletion). This exploitation method can have significant business impact, including data breaches, regulatory noncompliance, and reputational harm. 


context: go.gin.nosql.gin-mongo-nosql-taint.gin-mongo-nosqli-taint Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

# Vulnerability Breakdown
This vulnerability involves direct injection of untrusted user input into MongoDB queries, allowing attackers to manipulate query logic and potentially access unauthorized data.

1. **Key vulnerability elements**:
   - Query parameters from HTTP requests are directly incorporated into MongoDB query filters
   - No input validation or sanitization before query construction
   - Use of string interpolation in database query context
   - Go Gin framework handling HTTP requests with MongoDB backend

2. **Potential attack vectors**:
   - Injection of MongoDB operators like `$ne`, `$gt`, or `$regex` to alter query semantics
   - Manipulation of email parameter to bypass intended filtering logic
   - Construction of complex query objects to extract unintended data
   - Potential for data exfiltration through unauthorized read access

3. **Severity assessment**:
   - High confidentiality impact due to potential unauthorized access to all user records
   - No integrity impact as the vulnerability only affects read operations
   - No availability impact as service functionality remains intact
   - Network-accessible attack vector with low complexity and no authentication required

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

# Description
A high-severity NoSQL Injection vulnerability exists in Acme Corp's user management API built with the Go Gin framework and MongoDB. The vulnerability occurs in the `/user` endpoint where user-supplied query parameters are directly incorporated into MongoDB query filters without proper validation or sanitization.

```go
// Vulnerable code in the GET handler for /user endpoint
email := c.Query("email")
// Vulnerable pattern: directly injecting untrusted input into the query filter
filter := map[string]interface{}{"email": email}

var user map[string]interface{}
if err := collection.FindOne(context.Background(), filter).Decode(&user); err != nil {
  c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
  return
}
c.JSON(http.StatusOK, user)

```

This vulnerability allows attackers to inject MongoDB operators and modify the intended query logic. For example, an attacker could craft a request with a special JSON payload in the email parameter (e.g., `{"$ne":""}`) to bypass the email filtering and potentially retrieve all user records in the database. Unlike traditional SQL injection, NoSQL injection takes advantage of the document-oriented nature of MongoDB queries, allowing for complex operator-based manipulations.

# CVSS
**Score**: 7.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: High

The vulnerability scores 7.5 (High) on the CVSS v3.1 scale due to several significant factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely through the HTTP API endpoint, making it accessible to any attacker who can send HTTP requests to the server.

- **Low Attack Complexity (AC:L)**: Exploitation requires minimal specialized knowledge or complex preparation. A basic understanding of MongoDB query operators is sufficient to craft malicious inputs.

- **No Privileges Required (PR:N)**: The vulnerable endpoint doesn't require authentication, allowing unauthenticated attackers to exploit it.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without any action from legitimate users.

- **Unchanged Scope (S:U)**: The impact is limited to the vulnerable component (user management API) and its resources.

- **High Confidentiality Impact (C:H)**: An attacker can potentially access all user records in the database, including sensitive personal information, credentials, and other confidential data.

- **No Integrity Impact (I:N)**: The vulnerability only affects read operations as shown in the code sample, with no evidence that data modification is possible.

- **No Availability Impact (A:N)**: The vulnerability does not affect the system's availability, as it only impacts data retrieval operations.

It's important to note that only read operations are demonstrably vulnerable based on the provided code sample. While this presents a serious confidentiality risk, there is no evidence that write operations are similarly vulnerable, which is why integrity impact is rated as None.

# Exploitation Scenarios
**Scenario 1: Authentication Bypass and Data Exfiltration**
An attacker sends a request to the vulnerable endpoint with a specially crafted MongoDB operator in the email parameter:

```
GET /user?email={"$ne":""}

```

The server constructs the following MongoDB query filter:

```json
{"email": {"$ne": ""}}

```

This query searches for users where the email field is not equal to an empty string, effectively retrieving all user records in the database. The attacker now has unauthorized access to potentially sensitive user information, including personal details, contact information, and possibly even password hashes or other security credentials.

**Scenario 2: Targeted Data Extraction**
An attacker aware of a specific user (such as an administrator) could use MongoDB's regex operator to extract targeted data:

```
GET /user?email={"$regex":"admin"}

```

This would retrieve all users with "admin" in their email addresses, potentially giving the attacker access to administrative accounts.

**Scenario 3: Aggregate Data Extraction**
An attacker could use MongoDB's array operators to extract specific fields from all users in a single query:

```
GET /user?email={"$exists":true}

```

This query would return all users with an email field, effectively dumping the entire user collection. The attacker can then analyze this data to identify patterns, security weaknesses, or valuable information that could be leveraged in further attacks against the system or its users.

# Impact Analysis
**Business Impact:**
- Unauthorized disclosure of all user data, potentially including personal identifiable information (PII)
- Regulatory violations and potential fines (GDPR, CCPA, etc.) due to failure to protect user data
- Loss of customer trust and reputation damage when users discover their data has been compromised
- Potential legal liability from affected users whose data was exposed
- Business disruption during incident response, investigation, and remediation
- Costs associated with notification, credit monitoring, and other breach response measures

**Technical Impact:**
- Complete compromise of user database confidentiality through unrestricted read access
- Bypass of application's authentication and authorization mechanisms for data retrieval
- Potential for secondary attacks using harvested information (credential stuffing, phishing)
- Enumeration of internal user accounts including potential administrative users
- Exposure of internal data structures, potentially revealing application design details
- Challenges in detecting the attack as queries may appear legitimate in logs

It's important to note that based on the provided code sample, the vulnerability only affects read operations, with no evidence that data modification is possible. The impact is therefore limited to confidentiality breaches, though these can still have severe consequences for the organization and affected users.

# Technical Details
The vulnerability stems from the direct insertion of untrusted user input into MongoDB query filters without proper validation or sanitization. In the vulnerable code:

```go
email := c.Query("email")
filter := map[string]interface{}{"email": email}

```

The application assumes that `email` will be a simple string value. However, MongoDB's query language allows for complex operations using special operators that start with the "$" character.

**MongoDB Query Operators:**
MongoDB uses a document-based query language where filters can include operators like:
- `$ne`: Not equal to
- `$gt`/`$lt`: Greater than/less than
- `$regex`: Regular expression matching
- `$or`/`$and`: Logical operators
- `$where`: JavaScript expression evaluation

**Exploitation Mechanism:**
When the Go application parses the query parameter, it doesn't validate that the input is a simple string. When a request like `/user?email={"$ne":""}` is processed:

1. The Gin framework parses the parameter value as the string `{"$ne":""}`
2. This string is set as the value for the "email" key in the filter map
3. When the Go MongoDB driver processes this filter, it automatically converts the JSON string to a document structure
4. The resulting query becomes `{"email": {"$ne": ""}}` instead of looking for a specific email

**Technical Constraints:**
The exploitation requires that:
1. The input parameter must be properly formatted as a valid JSON string
2. The MongoDB driver must interpret and convert the string to a document/BSON structure
3. The API endpoint must return the results of the query manipulation

**Detection:**
This type of attack may be difficult to detect in logs since the queries might not look obviously malicious - they are valid MongoDB queries, just not the intended ones. Monitoring for unusual query patterns or excessive data retrieval might help identify exploitation attempts.

# Remediation Steps
## Implement Input Validation and Type Checking

**Priority**: P0

Add strict input validation to ensure query parameters match expected types and formats before using them in database operations:

```go
r.GET("/user", func(c *gin.Context) {
  email := c.Query("email")
  
  // Validate email format
  if !validateEmail(email) {
    c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
    return
  }
  
  // Ensure email is a simple string, not a JSON object
  if strings.Contains(email, "{") || strings.Contains(email, "$") {
    c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
    return
  }
  
  filter := map[string]interface{}{"email": email}
  
  var user map[string]interface{}{}
  if err := collection.FindOne(context.Background(), filter).Decode(&user); err != nil {
    c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
    return
  }
  c.JSON(http.StatusOK, user)
})

func validateEmail(email string) bool {
  // Use a regex pattern to validate email format
  pattern := `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
  match, _ := regexp.MatchString(pattern, email)
  return match
}

```

This solution adds two validation layers:
1. Checks if the email matches a valid email format using regex
2. Rejects inputs containing suspicious characters like '{' or '$' that could be used in MongoDB operators
## Use Parameterized Queries with MongoDB Primitive Types

**Priority**: P1

Refactor the code to use MongoDB's built-in query methods and type-safe primitives instead of generic interface maps:

```go
import (
  "context"
  "net/http"
  "regexp"

  "github.com/gin-gonic/gin"
  "go.mongodb.org/mongo-driver/bson"
  "go.mongodb.org/mongo-driver/mongo"
  "go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
  Email     string `bson:"email"`
  Name      string `bson:"name"`
  // Other user fields
}

func main() {
  r := gin.Default()
  client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
  if err != nil {
    panic(err)
  }
  collection := client.Database("acme").Collection("users")

  r.GET("/user", func(c *gin.Context) {
    email := c.Query("email")
    
    // Validate email format
    if !validateEmail(email) {
      c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
      return
    }
    
    // Use strongly-typed BSON document for queries
    filter := bson.D{{
      Key: "email", 
      Value: email, // Value is treated as a primitive string type
    }}
    
    var user User
    if err := collection.FindOne(context.Background(), filter).Decode(&user); err != nil {
      c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
      return
    }
    
    // Return only necessary fields to prevent information leakage
    c.JSON(http.StatusOK, gin.H{
      "name": user.Name,
      "email": user.Email,
    })
  })

  r.Run(":8080")
}

```

This approach uses MongoDB's `bson.D` type which treats values as primitive types rather than potential nested documents, preventing NoSQL injection. It also implements a structured User type with explicit field mappings, providing better type safety than generic map interfaces.


# References
* CWE-943 | [Improper Neutralization of Special Elements in Data Query Logic ('NoSQL Injection')](https://cwe.mitre.org/data/definitions/943.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
* Database-Security-CS | [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
