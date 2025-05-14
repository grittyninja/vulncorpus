# NoSQL Injection via Unsanitized User Input in MongoDB $where Operator

# Vulnerability Case
During a security assessment of Acme Corp's Go-based web service, built using the Gorilla Mux framework with MongoDB as the primary datastore, we identified a NoSQL injection vulnerability in the user query functionality. Analysis revealed that untrusted input from URL parameters was used directly to construct a JavaScript-based query via MongoDB's **$where** operator without proper sanitization. This flaw was uncovered when testing anomalous responses from endpoint queries that incorporated user input directly into the query filter. The vulnerability enables an attacker to inject malicious NoSQL statements, facilitating unauthorized data access.  

```go
package main

import (
        "context"
        "encoding/json"
        "fmt"
        "log"
        "net/http"

        "github.com/gorilla/mux"
        "go.mongodb.org/mongo-driver/bson"
        "go.mongodb.org/mongo-driver/mongo"
        "go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Database

func init() {
        // Establish connection to MongoDB
        client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
        if err != nil {
                log.Fatal(err)
        }
        db = client.Database("acme")
}

func getUser(w http.ResponseWriter, r *http.Request) {
        // Retrieve untrusted username from the query parameters
        username := r.URL.Query().Get("username")

        // Vulnerable: dynamically constructing a query using unsanitized user input
        // by embedding the input into a JavaScript expression for MongoDB's $where clause.
        queryFilter := bson.M{
                "$where": fmt.Sprintf("this.username == '%s' && this.active == true", username),
        }

        var user bson.M
        err := db.Collection("users").FindOne(context.Background(), queryFilter).Decode(&user)
        if err != nil {
                http.Error(w, "User not found", http.StatusNotFound)
                return
        }
        json.NewEncoder(w).Encode(user)
}

func main() {
        router := mux.NewRouter()
        router.HandleFunc("/user", getUser).Methods("GET")
        log.Println("Server listening on :8080")
        log.Fatal(http.ListenAndServe(":8080", router))
}
```

The vulnerability arises from directly injecting unsanitized user input into a NoSQL query via the **$where** clause, which interprets the input as JavaScript for query evaluation. An attacker can craft input that modifies the intended logic—for example, injecting payloads that always evaluate to true—to bypass authentication checks or retrieve all records from the collection. Exploitation could lead to unauthorized data disclosure, directly impacting the confidentiality of sensitive customer data. In a real-world scenario, leveraging such a vulnerability may allow threat actors to compromise the entire user database, potentially resulting in compliance violations, reputational harm, and significant financial loss for the business.  


context: go.gorilla.nosql.gorilla-mongo-nosqli-taint.gorilla-mongo-nosqli-taint Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

# Vulnerability Breakdown
This vulnerability involves a critical NoSQL injection weakness in Acme Corp's Go-based web service that uses the MongoDB database.

1. **Key vulnerability elements**:
   - User-controlled input (username parameter) is directly embedded into a MongoDB query's $where clause
   - The $where operator executes JavaScript expressions, making it particularly dangerous when combined with unsanitized input
   - String formatting via fmt.Sprintf() is used without any input validation or sanitization
   - The query is constructed dynamically using bson.M with the tainted input
   - The affected endpoint (/user) is accessible via HTTP GET requests

2. **Potential attack vectors**:
   - Injecting JavaScript expressions that always evaluate to true (e.g., `' || true`) to bypass authentication
   - Using JavaScript to access or modify fields not intended to be accessible
   - Executing time-delayed operations for blind NoSQL injection attacks
   - Potentially executing system commands if MongoDB is configured with certain privileges

3. **Severity assessment**:
   - High confidentiality impact as attackers can access unauthorized data
   - No integrity impact as the vulnerability only affects read operations
   - Low availability impact as the database service would likely remain operational
   - Network-accessible attack vector increases exploitability
   - Low complexity to exploit due to straightforward injection techniques

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

# Description
A severe NoSQL injection vulnerability exists in Acme Corp's Go-based web service that uses the Gorilla Mux framework with MongoDB. The vulnerability is located in the user query functionality where untrusted user input from URL parameters is directly embedded into a MongoDB query's `$where` clause without any sanitization.

```go
// Vulnerable code snippet
username := r.URL.Query().Get("username")
queryFilter := bson.M{
    "$where": fmt.Sprintf("this.username == '%s' && this.active == true", username),
}

```

The `$where` operator in MongoDB is particularly dangerous as it allows execution of arbitrary JavaScript expressions during query evaluation. By directly interpolating user input into this JavaScript expression using `fmt.Sprintf()`, the application creates a classic injection vulnerability. An attacker can craft malicious input to manipulate the query logic, potentially bypassing authentication controls, accessing unauthorized data, or even modifying database contents depending on the application's configuration.

# CVSS
**Score**: 7.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: High

The High severity rating (7.5) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is remotely exploitable via HTTP requests to the web service endpoint.
- **Low Attack Complexity (AC:L)**: Exploitation requires minimal technical skill and follows well-documented NoSQL injection techniques.
- **No Privileges Required (PR:N)**: An attacker doesn't need any authentication or authorization to exploit the vulnerability.
- **No User Interaction (UI:N)**: Exploitation can be performed directly without requiring actions from legitimate users.
- **Unchanged Scope (S:U)**: The impact is contained within the vulnerable component and doesn't enable access to other components.
- **High Confidentiality Impact (C:H)**: The vulnerability potentially exposes all user records in the database, including sensitive personal information.
- **No Integrity Impact (I:N)**: The vulnerability only affects read operations as seen in the code, with no ability to modify data.
- **No Availability Impact (A:N)**: The vulnerability does not directly impact system availability.

This vulnerability poses a significant risk because it allows anonymous attackers to easily bypass authentication and access controls to extract sensitive data from the MongoDB database with minimal technical skill required.

# Exploitation Scenarios
**Scenario 1: Authentication Bypass**
An attacker targets the vulnerable `/user` endpoint with a specially crafted query parameter: `username=' || true || '`. When injected into the $where clause, it transforms the query to `this.username == '' || true || '' && this.active == true`. Since `true` always evaluates to true in JavaScript, this condition matches all documents, effectively bypassing the username check. The attacker receives information for all users, not just the specific username they're authorized to view.

**Scenario 2: Data Exfiltration via Field Access**
The attacker exploits the JavaScript context to access fields that would normally be filtered out. By sending a query like `username=' || (function(){emit('hacked', this)})() || '`, they could potentially extract complete user documents including password hashes, personal information, and other sensitive data normally protected by query projections.

**Scenario 3: Conditional Information Leakage**
Using JavaScript's timing capabilities, an attacker performs a blind NoSQL injection attack. They send a series of requests with payloads like `username=' || (this.password.startsWith('a') && sleep(5000)) || '` and observe response times. By systematically testing different characters and measuring delays, they can gradually extract password information character by character without needing direct output.

**Scenario 4: Escalated Service Disruption**
An advanced attacker might leverage this vulnerability to execute resource-intensive operations. For example, using `username=' || (function(){while(1){}})() || '` could cause the MongoDB query to hang indefinitely. When executed across multiple connections, this could lead to resource exhaustion and potential denial of service for legitimate users.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer data potentially violating data protection regulations (GDPR, CCPA, etc.)
- Risk of complete database compromise exposing all user records
- Potential financial penalties from regulatory non-compliance
- Reputational damage if a breach is disclosed publicly
- Loss of customer trust and business relationships
- Costs associated with incident response, forensic investigation, and remediation
- Potential for legal action from affected customers

**Technical Impact:**
- Complete compromise of database confidentiality with access to all user records
- Potential for data manipulation depending on application context and database permissions
- Database performance degradation if attackers execute resource-intensive queries
- Information disclosure about database schema and application structure
- Exposure of internal implementation details that could facilitate further attacks
- Bypass of application-level access controls and security mechanisms
- Potential for persistent access if the vulnerability is used to modify authentication data

# Technical Details
The vulnerability stems from the direct embedding of unsanitized user input into a MongoDB query that uses the powerful `$where` operator. In MongoDB, the `$where` operator allows for the execution of arbitrary JavaScript expressions during query evaluation, making it particularly dangerous when combined with user-controlled input.

```go
func getUser(w http.ResponseWriter, r *http.Request) {
    // Retrieve untrusted username from the query parameters
    username := r.URL.Query().Get("username")

    // Vulnerable: dynamically constructing a query using unsanitized user input
    // by embedding the input into a JavaScript expression for MongoDB's $where clause.
    queryFilter := bson.M{
        "$where": fmt.Sprintf("this.username == '%s' && this.active == true", username),
    }

    var user bson.M
    err := db.Collection("users").FindOne(context.Background(), queryFilter).Decode(&user)
    if err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(user)
}

```

**Exploitation Mechanics:**

1. **String Interpolation Vulnerability**: The code uses `fmt.Sprintf()` to construct a query string with user input directly embedded into it. There's no validation, sanitization, or escaping of this input.

2. **JavaScript Injection Context**: Since the `$where` operator evaluates JavaScript, an attacker can inject valid JavaScript expressions that alter the query logic. For example:
   - Input: `' || true //`
   - Resulting query: `this.username == '' || true // && this.active == true`
   - The comment (`//`) nullifies the rest of the condition, and the logical OR with `true` ensures the expression always evaluates to true.

3. **MongoDB Query Execution**: When this query runs, MongoDB evaluates the JavaScript expression for each document in the collection. If the expression evaluates to true, the document is included in the results.

**Attack Variants:**

1. **Simple Bypass**: `' || true ||'`
   - Transforms to: `this.username == '' || true || '' && this.active == true`
   - Always evaluates to true for all documents

2. **Conditional Data Extraction**: `' || (this.creditCardNumber && sleep(5000)) || '`
   - Causes a delay only if the document contains a credit card number field
   - Enables blind extraction of data structure

3. **JavaScript Function Execution**: `' || (function(){/* malicious code */})() || '`
   - Executes arbitrary JavaScript functions within the database context

4. **Document Access**: `' || Object.keys(this) || '`
   - Returns field names, potentially revealing database schema

This vulnerability is particularly severe because:

1. The affected endpoint is accessible without authentication
2. The MongoDB query execution happens server-side, bypassing typical client-side protections
3. The JavaScript context allows for complex attack patterns beyond simple string manipulation
4. The `$where` operator is inherently risky and enables powerful attacks when combined with unsanitized input

# Remediation Steps
## Replace $where with Safe Query Operators

**Priority**: P0

Eliminate the use of the `$where` operator entirely and replace it with standard MongoDB query operators that don't execute JavaScript:

```go
func getUser(w http.ResponseWriter, r *http.Request) {
    // Retrieve username from the query parameters
    username := r.URL.Query().Get("username")
    
    // Construct a query using standard MongoDB operators
    queryFilter := bson.M{
        "username": username,
        "active": true,
    }
    
    var user bson.M
    err := db.Collection("users").FindOne(context.Background(), queryFilter).Decode(&user)
    if err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(user)
}

```

This approach eliminates the vulnerability by:
1. Using direct field comparisons instead of JavaScript evaluation
2. Removing the string interpolation entirely
3. Passing the username parameter directly to MongoDB, which handles it as a literal value rather than executable code
## Implement Input Validation and Parameterized Queries

**Priority**: P1

If more complex queries are needed, implement strict input validation and use parameterized queries:

```go
func getUser(w http.ResponseWriter, r *http.Request) {
    // Retrieve username from the query parameters
    username := r.URL.Query().Get("username")
    
    // Validate input - example of a basic validation
    if !isValidUsername(username) {
        http.Error(w, "Invalid username format", http.StatusBadRequest)
        return
    }
    
    // Use MongoDB's aggregation pipeline for more complex queries
    pipeline := mongo.Pipeline{
        bson.D{{
            "$match", bson.D{
                {"username", username},
                {"active", true},
            },
        }},
        // Add additional pipeline stages as needed
    }
    
    cursor, err := db.Collection("users").Aggregate(context.Background(), pipeline)
    if err != nil {
        http.Error(w, "Error processing request", http.StatusInternalServerError)
        return
    }
    defer cursor.Close(context.Background())
    
    var results []bson.M
    if err = cursor.All(context.Background(), &results); err != nil {
        http.Error(w, "Error retrieving results", http.StatusInternalServerError)
        return
    }
    
    if len(results) == 0 {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    
    json.NewEncoder(w).Encode(results[0])
}

func isValidUsername(username string) bool {
    // Implement validation logic - for example, alphanumeric with limited special chars
    usernameRegex := regexp.MustCompile("^[a-zA-Z0-9_-]{3,30}$")
    return usernameRegex.MatchString(username)
}

```

This implementation:
1. Validates input against a strict pattern before using it in queries
2. Uses MongoDB's structured query operators instead of JavaScript evaluation
3. Employs the aggregation pipeline for complex queries while maintaining security
4. Provides appropriate error handling and user feedback


# References
* CWE-943 | [Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
