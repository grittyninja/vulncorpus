# LDAP Injection in Authentication Module

# Vulnerability Case
During a routine static code review of Acme Corp's C++ authentication module interfacing with the LDAP directory, we observed that user-supplied input was directly concatenated into an LDAP query filter without proper escaping. This issue was uncovered when test inputs containing special LDAP characters altered the intended query structure, revealing the potential for LDAP injection. The vulnerability, observed in a system using OpenLDAP on Linux and integrated with Acme's custom C++ codebase, allows attackers to manipulate query parameters arbitrarily. Improperly sanitized input can lead to unauthorized disclosure of sensitive directory information or bypass of access controls. Such exploitation could directly impact business-critical operations by facilitating unauthorized access to sensitive user data and disrupting the authentication process.

```cpp
#include <iostream>
#include <ldap.h>
#include <string>

int main() {
    std::string userInput;
    std::cout << "Enter username: ";
    std::getline(std::cin, userInput);

    // Vulnerable LDAP filter: direct concatenation of untrusted input
    std::string ldapFilter = "(&(objectClass=user)(uid=" + userInput + "))";

    LDAP* ldapConn = nullptr;
    int rc = ldap_initialize(&ldapConn, "ldap://ldap.acme.local");
    if (rc != LDAP_SUCCESS) {
        std::cerr << "LDAP initialization failed: " << ldap_err2string(rc)
                  << std::endl;
        return 1;
    }

    LDAPMessage* results = nullptr;
    // The unescaped ldapFilter may allow LDAP injection attacks
    rc = ldap_search_ext_s(
        ldapConn,
        "ou=users,dc=acme,dc=local",
        LDAP_SCOPE_SUBTREE,
        ldapFilter.c_str(),
        nullptr,
        0,
        nullptr,
        nullptr,
        nullptr,
        0,
        &results);

    if (rc != LDAP_SUCCESS) {
        std::cerr << "LDAP search failed: " << ldap_err2string(rc)
                  << std::endl;
    } else {
        std::cout << "LDAP search executed successfully." << std::endl;
    }

    ldap_msgfree(results);
    ldap_unbind_ext(ldapConn, nullptr, nullptr);
    return 0;
}
```


The vulnerability stems from building the LDAP filter by directly concatenating untrusted user input without sanitization, thereby allowing LDAP meta-characters to manipulate the query syntax. An attacker could inject crafted input to modify the query, potentially enumerating directory entries or bypassing authentication checks. Exploitation may result in unauthorized data access and privilege escalation, greatly increasing the risk of sensitive information leakage and operational disruption in environments utilizing OpenLDAP or similar LDAP services.

context: cpp.lang.security.ldap.ldap-injection-filter.ldap-injection-filter Untrusted input might be used to build an LDAP query, which can allow attackers to run arbitrary LDAP queries. If an LDAP query must contain untrusted input then it must be escaped.

# Vulnerability Breakdown
This vulnerability involves improper handling of user input in an LDAP authentication module where user-supplied data is directly concatenated into LDAP query filters without proper sanitization or validation.

1. **Key vulnerability elements**:
   - User input is directly concatenated into LDAP filter strings without escaping
   - No input validation is performed before using the data in queries
   - Special LDAP filter characters can alter the intended query structure
   - Implementation in C++ using OpenLDAP on Linux

2. **Potential attack vectors**:
   - Injecting LDAP meta-characters to escape the filter context
   - Adding OR conditions to bypass authentication checks
   - Appending wildcard characters to perform directory enumeration
   - Using NULL bytes or encoding tricks to manipulate query parsing

3. **Severity assessment**:
   - High confidentiality impact due to potential for unauthorized data access
   - Low integrity impact as attackers can manipulate query results but not directly modify LDAP data
   - Local attack vector as it requires access to the authentication module interface
   - Low attack complexity as crafting malicious input is straightforward

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Local (L) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
A critical LDAP injection vulnerability has been identified in Acme Corp's C++ authentication module that interfaces with the corporate LDAP directory. The vulnerability stems from user-supplied input being directly concatenated into LDAP filter strings without proper escaping or validation, allowing attackers to manipulate the structure of LDAP queries.

In the vulnerable code, user input for the username field is directly incorporated into an LDAP filter without sanitization:

```cpp
std::string ldapFilter = "(&(objectClass=user)(uid=" + userInput + "))";  // Vulnerable line

```

LDAP filters use a specific syntax with special characters such as parentheses, asterisks, ampersands, and vertical bars that have semantic meaning. By injecting these characters, attackers can modify the logic of queries, potentially bypassing authentication controls or extracting unauthorized information from the directory. This vulnerability could allow unauthorized access to sensitive user data and potentially lead to authentication bypass or information disclosure.

# CVSS
**Score**: 6.8 \
**Vector**: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N \
**Severity**: Medium

The Medium severity rating (6.8) is based on the following factors:

- **Local Attack Vector (AV:L)**: The vulnerability requires access to the authentication module's interface, limiting the attack surface to local access points or specific network access to the LDAP system.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability is straightforward and does not require special conditions or sophisticated techniques. An attacker simply needs to craft input containing LDAP special characters.

- **No Privileges Required (PR:N)**: The vulnerability can be exploited without any authentication or special privileges, as it affects the authentication process itself.

- **No User Interaction Required (UI:N)**: The vulnerability can be exploited without any action from a legitimate user.

- **Unchanged Scope (S:U)**: The impact is limited to the vulnerable component itself and doesn't extend to other components.

- **High Confidentiality Impact (C:H)**: Successful exploitation could lead to unauthorized disclosure of all user information in the LDAP directory, including potentially sensitive attributes.

- **Low Integrity Impact (I:L)**: The attacker can manipulate query results but cannot directly modify the data stored in the LDAP directory.

- **No Availability Impact (A:N)**: The vulnerability doesn't directly impact the availability of the system or service.

# Exploitation Scenarios
**Scenario 1: Authentication Bypass**
An attacker enters the following as a username: `*)(|(uid=*)`. This input transforms the LDAP filter into:

```
(&(objectClass=user)(uid=*)(|(uid=*)))

```

This modified filter will match any user object in the directory, effectively bypassing the intended authentication check. The attacker can then gain unauthorized access to the system without knowing valid credentials.

**Scenario 2: Information Disclosure and Enumeration**
An attacker systematically probes the directory by entering patterns like `a*))(&(1=0`. This input creates a filter like:

```
(&(objectClass=user)(uid=a*))(&(1=0)))

```

By varying the starting character and analyzing response times or error messages, the attacker can enumerate valid usernames beginning with different letters. This technique allows mapping of the organization's user directory without proper authorization.

**Scenario 3: Attribute Harvesting**
An attacker injects `*)(uid=*)(mail=*`. This transforms the LDAP query to search for all users with email addresses, potentially retrieving email information for the entire directory:

```
(&(objectClass=user)(uid=*)(uid=*)(mail=*))

```

By systematically targeting different attributes (mail, telephoneNumber, title, department), the attacker can harvest sensitive personal and organizational information from the directory.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive user information stored in the LDAP directory
- Potential breach of confidential employee data including contact information, roles, and organizational structure
- Bypass of authentication mechanisms leading to unauthorized system access
- Violation of data protection regulations and potential compliance penalties
- Loss of customer trust if personal information is exposed
- Operational disruption if authentication services are compromised

**Technical Impact:**
- Unauthorized enumeration of directory structure and user accounts
- Discovery of internal organizational hierarchy and reporting structures
- Potential escalation to broader network access if authentication controls are bypassed
- Ability to harvest email addresses and other contact information for spear-phishing campaigns
- Mapping of internal systems through information disclosure
- Extraction of user attributes beyond those intended to be accessible
- Potential for lateral movement within connected systems that rely on the LDAP authentication mechanism

# Technical Details
The vulnerability exists in Acme Corp's C++ authentication module that interfaces with the LDAP directory. The core issue is the direct concatenation of user input into LDAP filter strings without proper sanitization:

```cpp
// Vulnerable code snippet
std::string userInput;
std::cout << "Enter username: ";
std::getline(std::cin, userInput);

// Vulnerable LDAP filter: direct concatenation of untrusted input
std::string ldapFilter = "(&(objectClass=user)(uid=" + userInput + "))";

// Using the tainted filter in a search operation
rc = ldap_search_ext_s(
    ldapConn,
    "ou=users,dc=acme,dc=local",
    LDAP_SCOPE_SUBTREE,
    ldapFilter.c_str(),
    nullptr,
    0,
    nullptr,
    nullptr,
    nullptr,
    0,
    &results);

```

**LDAP Injection Mechanics:**

LDAP filters use a specific syntax that includes special characters with semantic meaning:
- Parentheses `()` group expressions
- Ampersand `&` represents logical AND
- Vertical bar `|` represents logical OR
- Asterisk `*` serves as a wildcard
- Exclamation point `!` represents logical NOT

By injecting these characters, attackers can manipulate the query structure. For example:

1. **Original intended filter:**
   ```
   (&(objectClass=user)(uid=john))
   
   ```

2. **Manipulated filter with injection `*)(|(uid=*`:**
   ```
   (&(objectClass=user)(uid=*)(|(uid=*)))
   
   ```
   This creates a condition that matches any user object.

3. **Filter with information disclosure injection `*)(mail=*)(objectClass=*`:**
   ```
   (&(objectClass=user)(uid=*)(mail=*)(objectClass=*))
   
   ```
   This pulls additional attributes beyond the intended scope.

The vulnerability is particularly dangerous because:
1. It occurs during authentication, providing an entry point to the system
2. It can expose sensitive user data from the directory
3. It might be leveraged to bypass authentication controls entirely
4. The LDAP directory typically contains comprehensive organizational information

# Remediation Steps
## Implement LDAP Input Sanitization

**Priority**: P0

Replace direct input concatenation with proper LDAP escaping to neutralize special characters:

```cpp
#include <iostream>
#include <ldap.h>
#include <string>

// Function to escape LDAP special characters
std::string ldapEscape(const std::string& input) {
    std::string escaped;
    for (char c : input) {
        // Characters requiring escaping in LDAP filters: * ( ) \ / NUL
        switch (c) {
            case '*':
                escaped += "\\2a";
                break;
            case '(':
                escaped += "\\28";
                break;
            case ')':
                escaped += "\\29";
                break;
            case '\\':
                escaped += "\\5c";
                break;
            case '/':
                escaped += "\\2f";
                break;
            case '\0':
                escaped += "\\00";
                break;
            default:
                escaped += c;
        }
    }
    return escaped;
}

int main() {
    std::string userInput;
    std::cout << "Enter username: ";
    std::getline(std::cin, userInput);

    // Sanitize the user input before using it in the LDAP filter
    std::string sanitizedInput = ldapEscape(userInput);
    std::string ldapFilter = "(&(objectClass=user)(uid=" + sanitizedInput + "))";

    // Continue with LDAP operations using the sanitized filter
    // ...
}

```

This approach ensures that any special characters in the user input are properly escaped, preventing them from altering the LDAP filter's logical structure. The escaping follows the RFC 4515 standard for LDAP filters, converting special characters to their hexadecimal representation prefixed with a backslash.
## Implement Input Validation

**Priority**: P1

Add strict input validation to reject potentially malicious inputs before processing:

```cpp
#include <iostream>
#include <ldap.h>
#include <string>
#include <regex>

bool validateUsername(const std::string& username) {
    // Define a regex pattern for valid usernames
    // This example allows alphanumeric characters, dots, hyphens, and underscores
    std::regex pattern("^[a-zA-Z0-9._-]{1,64}$");
    
    // Check if the username matches the pattern
    return std::regex_match(username, pattern);
}

int main() {
    std::string userInput;
    std::cout << "Enter username: ";
    std::getline(std::cin, userInput);

    // Validate the user input
    if (!validateUsername(userInput)) {
        std::cerr << "Invalid username format. Username must contain only "
                  << "alphanumeric characters, dots, hyphens, and underscores." << std::endl;
        return 1;
    }

    // Even with validation, still escape the input for defense in depth
    // [Include the escaping function from remediation step 1]
    std::string sanitizedInput = ldapEscape(userInput);
    std::string ldapFilter = "(&(objectClass=user)(uid=" + sanitizedInput + "))";

    // Continue with LDAP operations
    // ...
}

```

This validation approach ensures that only usernames matching a predetermined safe pattern are accepted. By implementing both input validation and proper escaping (from the P0 remediation), a defense-in-depth strategy is achieved that significantly reduces the risk of LDAP injection attacks.


# References
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-89 | [Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* CWE-77 | [Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
