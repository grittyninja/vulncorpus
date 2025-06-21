# NoSQL Injection in Golang MongoDB API Endpoint

# Vulnerability Case
During our recent security assessment of Acme Corp's backend services built with Golang and MongoDB, we discovered that unvalidated user input was directly used to construct database queries, causing a severe NoSQL injection vulnerability. Our investigation revealed that an API endpoint accepting JSON query parameters fails to properly sanitize the tainted input, enabling an attacker to inject malicious query operators. The vulnerability was identified during dynamic testing and log analysis where specially crafted input altered the intended query logic. Exploitation could lead to unauthorized data disclosure, adversely impacting the confidentiality of the system. The affected technology stack includes Golang's `net/http` package alongside the official MongoDB Go Driver.

```go
package main

import (
        "context"
        "encoding/json"
        "net/http"

        "go.mongodb.org/mongo-driver/bson"
        "go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection // initialized elsewhere

// FindUser is vulnerable to NoSQL Injection due to the use of untrusted input
func FindUser(w http.ResponseWriter, r *http.Request) {
        // Capture user input from query parameters
        // Expected to be a JSON object representing a query filter, e.g.,
        // {"user_id": "12345"} but can be manipulated to include MongoDB operators.
        userInput := r.URL.Query().Get("search")

        var query bson.M
        // Vulnerability: Directly parsing unsanitized user input into a query object.
        if err := json.Unmarshal([]byte(userInput), &query); err != nil {
                http.Error(w, "Invalid query", http.StatusBadRequest)
                return
        }

        // Execute the query against the MongoDB collection.
        cursor, err := userCollection.Find(context.Background(), query)
        if err != nil {
                http.Error(w, "Database error", http.StatusInternalServerError)
                return
        }
        defer cursor.Close(context.Background())

        // Process and encode the results.
        if err := json.NewEncoder(w).Encode(cursor); err != nil {
                http.Error(w, "Encoding error", http.StatusInternalServerError)
                return
        }
}
```

The vulnerability arises because the API endpoint accepts a JSON string via the `search` query parameter and directly converts it into a MongoDB query without sanitization. An attacker can exploit this by crafting a malicious payload—for example, injecting operators like `{$ne": null}` or `{$or": [{"user_id": "12345"}, {}]}`—to alter the query logic. Such exploitation might enable the retrieval of unauthorized data, thereby severely impacting business operations by undermining data confidentiality. The attack leverages the inherent flexibility of MongoDB's query language when combined with insecure application logic written in Golang.


context: go.net.nosql.net-mongo-nosqli-taint.net-mongo-nosqli-taint Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

# Vulnerability Breakdown
This is a severe NoSQL injection vulnerability in Acme Corp's Golang backend service that uses MongoDB. The vulnerability stems from insecure handling of user input in database queries.

1. **Key vulnerability elements**:
   - User-supplied JSON is directly unmarshaled into a MongoDB query object (`bson.M`)
   - No sanitization or validation of input before query execution
   - Affected component is the `FindUser` API endpoint in the Golang service
   - MongoDB's flexible query language makes injection particularly dangerous
   - Direct use of user input in security-critical database operations

2. **Potential attack vectors**:
   - Injection of MongoDB operators like `$ne`, `$gt`, `$or`, etc., to alter query logic
   - Manipulation of search parameters to bypass filtering restrictions
   - Construction of complex queries to expose unauthorized data
   - Extraction of sensitive information through carefully crafted queries

3. **Severity assessment**:
   - High confidentiality impact due to potential access to all stored data
   - No direct integrity impact as the vulnerable function only performs read operations
   - No direct availability impact as the function doesn't modify or delete data
   - Network-accessible attack vector with no special conditions needed
   - No authentication required to exploit the vulnerability

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
A critical NoSQL injection vulnerability has been identified in Acme Corp's backend services built with Golang and MongoDB. The vulnerability exists in the `FindUser` API endpoint which accepts user input via the `search` query parameter and directly converts it into a MongoDB query without proper validation or sanitization.

```go
// Vulnerable code:
userInput := r.URL.Query().Get("search")
var query bson.M
// Vulnerability: Directly parsing unsanitized user input into a query object
if err := json.Unmarshal([]byte(userInput), &query); err != nil {
    http.Error(w, "Invalid query", http.StatusBadRequest)
    return
}
// Executing the potentially malicious query
cursor, err := userCollection.Find(context.Background(), query)

```

This implementation allows attackers to inject MongoDB operators and modify query logic, potentially enabling unauthorized access to all data in the MongoDB collection. For example, an attacker could supply a payload containing special MongoDB operators like `{"$ne": null}` or `{"$or": [{}, {"restricted": false}]}` to bypass security restrictions and access unauthorized data.

# CVSS
**Score**: 7.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: High

This vulnerability is rated as High (CVSS score: 7.5) based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is remotely exploitable through the API endpoint
- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and doesn't require special conditions or significant resources
- **No Privileges Required (PR:N)**: The vulnerable endpoint appears to be accessible without authentication
- **No User Interaction (UI:N)**: No action is required from users for the vulnerability to be exploited
- **Unchanged Scope (S:U)**: The vulnerability affects only the MongoDB database and associated application
- **High Confidentiality Impact (C:H)**: An attacker can potentially access all data in the collection, including sensitive user information
- **No Integrity Impact (I:N)**: The vulnerable function only performs read operations and doesn't directly enable data modification
- **No Availability Impact (A:N)**: The vulnerable function doesn't have the capability to delete data or disrupt service

The combination of a network-accessible vector, no required privileges, and high impact to confidentiality makes this a serious vulnerability requiring immediate attention, even though the direct impact is limited to data exposure rather than modification.

# Exploitation Scenarios
**Scenario 1: Data Exfiltration**
An attacker identifies the vulnerable endpoint and constructs a malicious query parameter:
```
GET /api/users?search={"username":{"$ne":""}} HTTP/1.1
Host: api.acmecorp.com

```
This query uses MongoDB's `$ne` (not equal) operator to match all users with a username not equal to an empty string—effectively returning all user records. This allows the attacker to bypass intended access controls and exfiltrate the entire user database, including sensitive personal information or business data.

**Scenario 2: Authentication Bypass**
Assuming the application has a login function that queries the database to verify credentials:
```
GET /api/login?search={"username":"admin","password":{"$exists":true}} HTTP/1.1
Host: api.acmecorp.com

```
Instead of providing a valid password, the attacker uses the `$exists` operator to match any record where the password field exists, bypassing authentication and gaining unauthorized access to the admin account.

**Scenario 3: Data Structure Mapping**
An attacker progressively maps out the database structure:
```
GET /api/users?search={"$where":"return Object.keys(this).length > 5"} HTTP/1.1
Host: api.acmecorp.com

```
This query uses the `$where` operator with JavaScript execution to return documents with more than 5 fields, allowing the attacker to understand the document structure. By iterating through different queries, the attacker gradually builds a complete map of the database schema, field names, and data patterns.

**Scenario 4: Selective Data Extraction**
An attacker uses logical operators to perform targeted data extraction:
```
GET /api/users?search={"$or":[{"role":"admin"},{"hasPaymentInfo":true}]} HTTP/1.1
Host: api.acmecorp.com

```
This query would return all admin users or users with payment information, allowing the attacker to focus on high-value targets for further exploitation.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to all customer data, leading to severe privacy violations
- Regulatory penalties under laws like GDPR, CCPA, or industry-specific regulations
- Legal liability from affected users whose data was exposed
- Reputational damage and loss of customer trust if a breach is disclosed
- Financial impact from incident response, forensic investigation, and remediation costs
- Potential business disruption if sensitive operational data is exposed
- Loss of competitive advantage if proprietary information is exposed

**Technical Impact:**
- Complete compromise of database confidentiality—attackers may access all stored data
- Exposure of sensitive information including user credentials, personal information, or business data
- Authentication bypass vulnerabilities compromising access controls
- Exposure of internal API structure and database schema to attackers
- Information gathering for more sophisticated follow-up attacks
- Circumvention of intended access controls and data filtering
- Potential for excessive database load from complex injected queries
- Log pollution making detection of actual malicious activity more difficult

# Technical Details
The vulnerability occurs in the `FindUser` function of the Golang backend service that interacts with MongoDB. The specific issue lies in how user input is processed and used to construct database queries.

```go
func FindUser(w http.ResponseWriter, r *http.Request) {
    // Capture user input from query parameters
    userInput := r.URL.Query().Get("search")

    var query bson.M
    // Vulnerability: Directly parsing unsanitized user input into a query object.
    if err := json.Unmarshal([]byte(userInput), &query); err != nil {
        http.Error(w, "Invalid query", http.StatusBadRequest)
        return
    }

    // Execute the query against the MongoDB collection.
    cursor, err := userCollection.Find(context.Background(), query)
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer cursor.Close(context.Background())

    // Process and encode the results.
    if err := json.NewEncoder(w).Encode(cursor); err != nil {
        http.Error(w, "Encoding error", http.StatusInternalServerError)
        return
    }
}

```

**Vulnerability Mechanism:**

1. The function accepts a `search` query parameter expected to contain a JSON string
2. This JSON string is directly unmarshaled into a `bson.M` object (a map[string]interface{} type in MongoDB's Go driver)
3. The resulting map is used directly as a MongoDB query without any validation or sanitization
4. MongoDB's flexible query language allows operators like `$ne`, `$gt`, `$or`, etc., which can be injected to manipulate query logic

**MongoDB Query Operators:**
MongoDB provides powerful query operators that can be exploited in this context:

- Comparison operators: `$eq`, `$ne`, `$gt`, `$gte`, `$lt`, `$lte`
- Logical operators: `$and`, `$or`, `$nor`, `$not`
- Element operators: `$exists`, `$type`
- Evaluation operators: `$regex`, `$text`, `$where`

**Example Exploitation:**

Normal expected query parameter:
```
?search={"username":"john"}

```

Malicious query parameter using NoSQL injection:
```
?search={"username":{"$ne":""},"role":"admin"}

```

This would match all admin users instead of just finding users with the username "john".

**Technical Impact Mechanism:**

When the injected query is executed against the MongoDB collection, it alters the intended filtering logic and can:

1. Return more records than intended (breaking confidentiality)
2. Return different records than intended (breaking access controls)
3. Potentially cause performance issues with complex queries

It's important to note that the vulnerable code shown only performs read operations (Find). Unlike SQL injection which can often enable data modification through operations like UPDATE or DELETE, this specific vulnerability as shown only impacts data confidentiality, not integrity or availability.

The MongoDB Go driver does not automatically sanitize inputs, placing the responsibility on the developer to implement proper validation and sanitization.

# Remediation Steps
## Implement Input Validation and Query Structure Control

**Priority**: P0

Replace direct JSON unmarshaling with a structured approach that explicitly defines allowed fields and operations:

```go
func FindUser(w http.ResponseWriter, r *http.Request) {
    // Parse and validate user input with explicit structure
    userInput := r.URL.Query().Get("search")
    
    // Define a strict search structure that only accepts known fields
    type SafeUserSearch struct {
        Username    string `json:"username,omitempty"`
        Email       string `json:"email,omitempty"`
        FirstName   string `json:"first_name,omitempty"`
        LastName    string `json:"last_name,omitempty"`
        // Add other allowed search fields
    }
    
    var safeSearch SafeUserSearch
    if err := json.Unmarshal([]byte(userInput), &safeSearch); err != nil {
        http.Error(w, "Invalid search parameters", http.StatusBadRequest)
        return
    }
    
    // Convert the safe structure to a MongoDB query
    query := bson.M{}
    
    // Only add non-empty fields to the query
    if safeSearch.Username != "" {
        query["username"] = safeSearch.Username
    }
    if safeSearch.Email != "" {
        query["email"] = safeSearch.Email
    }
    if safeSearch.FirstName != "" {
        query["first_name"] = safeSearch.FirstName
    }
    if safeSearch.LastName != "" {
        query["last_name"] = safeSearch.LastName
    }
    
    // Execute the now-safe query
    cursor, err := userCollection.Find(context.Background(), query)
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer cursor.Close(context.Background())
    
    // Process results as before
    var results []bson.M
    if err := cursor.All(context.Background(), &results); err != nil {
        http.Error(w, "Error processing results", http.StatusInternalServerError)
        return
    }
    
    if err := json.NewEncoder(w).Encode(results); err != nil {
        http.Error(w, "Encoding error", http.StatusInternalServerError)
        return
    }
}

```

This approach:
1. Defines an explicit structure that only allows specific fields
2. Prevents injection of MongoDB operators
3. Constructs a clean query with only the validated fields
4. Eliminates the possibility of malicious query manipulation
## Implement Advanced Query Builder with Operator Controls

**Priority**: P1

For cases requiring more complex queries while maintaining security, implement a query builder that safely translates allowed operations:

```go
func FindUser(w http.ResponseWriter, r *http.Request) {
    // Parse the search parameters
    userInput := r.URL.Query().Get("search")
    
    // Define a safe query request structure that includes limited operations
    type QueryCondition struct {
        Field    string `json:"field"`
        Operator string `json:"operator"` // "eq", "contains", "startsWith", etc.
        Value    string `json:"value"`
    }
    
    type SafeQueryRequest struct {
        Conditions []QueryCondition `json:"conditions"`
        Limit      int              `json:"limit,omitempty"`
        Skip       int              `json:"skip,omitempty"`
    }
    
    var safeQuery SafeQueryRequest
    if err := json.Unmarshal([]byte(userInput), &safeQuery); err != nil {
        http.Error(w, "Invalid search format", http.StatusBadRequest)
        return
    }
    
    // Validate field names against whitelist
    allowedFields := map[string]bool{"username": true, "email": true, "first_name": true, "last_name": true}
    
    // Validate operators against whitelist
    allowedOperators := map[string]bool{"eq": true, "contains": true, "startsWith": true}
    
    // Build MongoDB query from safe structure
    query := bson.M{}
    
    for _, condition := range safeQuery.Conditions {
        // Validate field is allowed
        if !allowedFields[condition.Field] {
            http.Error(w, "Invalid search field", http.StatusBadRequest)
            return
        }
        
        // Validate operator is allowed
        if !allowedOperators[condition.Operator] {
            http.Error(w, "Invalid search operator", http.StatusBadRequest)
            return
        }
        
        // Safely translate to MongoDB operators
        switch condition.Operator {
        case "eq":
            query[condition.Field] = condition.Value
        case "contains":
            query[condition.Field] = bson.M{"$regex": primitive.Regex{Pattern: regexp.QuoteMeta(condition.Value), Options: "i"}}
        case "startsWith":
            query[condition.Field] = bson.M{"$regex": primitive.Regex{Pattern: "^" + regexp.QuoteMeta(condition.Value), Options: ""}}
        }
    }
    
    // Apply pagination safely
    findOptions := options.Find()
    if safeQuery.Limit > 0 && safeQuery.Limit <= 100 { // Set reasonable limits
        findOptions.SetLimit(int64(safeQuery.Limit))
    } else {
        findOptions.SetLimit(10) // Default limit
    }
    
    if safeQuery.Skip > 0 {
        findOptions.SetSkip(int64(safeQuery.Skip))
    }
    
    // Execute safe query
    cursor, err := userCollection.Find(context.Background(), query, findOptions)
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer cursor.Close(context.Background())
    
    // Process and return results
    var results []bson.M
    if err := cursor.All(context.Background(), &results); err != nil {
        http.Error(w, "Error processing results", http.StatusInternalServerError)
        return
    }
    
    if err := json.NewEncoder(w).Encode(results); err != nil {
        http.Error(w, "Encoding error", http.StatusInternalServerError)
        return
    }
}

```

This implementation:
1. Provides a flexible but controlled query interface
2. Explicitly whitelists allowed fields and operations
3. Safely translates high-level operations to MongoDB queries
4. Implements pagination controls with reasonable limits
5. Prevents any direct injection of MongoDB operators


# References
* CWE-943 | [Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
