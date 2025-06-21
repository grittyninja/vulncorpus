# LDAP Injection in Authentication Module

# Vulnerability Case
During a security assessment of Acme Corp's C++ LDAP authentication module, we discovered that untrusted user input is directly concatenated into LDAP distinguished names (DN) without proper escaping. This vulnerability was identified when reviewing the module’s source code and testing against crafted inputs, leading to a scenario where LDAP queries are manipulated arbitrarily. In this context, user-supplied data is embedded into the LDAP query string without sanitization, bypassing input validation mechanisms inherent in libraries such as OpenLDAP. The issue was observed during dynamic testing on a Linux system running the OpenLDAP toolkit, revealing the potential for unauthorized directory access. Such LDAP Injection (DN) vulnerabilities can critically compromise the integrity and confidentiality of directory services.

```cpp
#include <iostream>
#include <string>
#include <ldap.h>

int main() {
    // Simulated untrusted input from a user interface
    std::string userInput;
    std::cout << "Enter username: ";
    std::cin >> userInput;

    // Vulnerable LDAP filter construction: unescaped input directly inserted
    std::string ldapFilter = "(uid=" + userInput + ")";

    LDAP* ld;
    int result = ldap_initialize(&ld, \ldap://localhost\"");
    if (result != LDAP_SUCCESS) {
        std::cerr << "LDAP initialization failed: 
                  << ldap_err2string(result) << std::endl;
        return 1;
    }

    // Perform an LDAP search using the vulnerable filter
    LDAPMessage* searchResult = nullptr;
    result = ldap_search_s(ld, "dc=acme,dc=corp", LDAP_SCOPE_SUBTREE,
                           ldapFilter.c_str(), nullptr, 0, &searchResult);
    
    if (result != LDAP_SUCCESS) {
        std::cerr << "LDAP search failed: " 
                  << ldap_err2string(result) << std::endl;
    } else {
        std::cout << "LDAP search executed with filter: "
                  << ldapFilter << std::endl;
    }

    ldap_msgfree(searchResult);
    ldap_unbind_ext(ld, nullptr, nullptr);
    return 0;
}
```

An attacker can exploit this vulnerability by inserting LDAP metacharacters into the username field, thereby altering the intended structure of the DN. Such manipulation could lead to arbitrary modifications of the LDAP query, enabling unauthorized disclosure or modification of directory data. In a production environment using OpenLDAP on a Linux server, exploitation may result in unauthorized access to sensitive user credentials, privilege escalation, and potential internal lateral movement. The business impact is severe — compromising the confidentiality and integrity of critical directory services, which could lead to data breaches, regulatory compliance failures, and significant reputational harm.

context: cpp.lang.security.ldap.ldap-injection-dn.ldap-injection-dn Untrusted input might be used to build an LDAP query, which can allow attackers to run arbitrary LDAP queries. If an LDAP query must contain untrusted input then it must be escaped.

# Vulnerability Breakdown
This vulnerability involves the direct concatenation of untrusted user input into LDAP distinguished names (DN) without proper sanitization or escaping, creating an LDAP injection vulnerability.

1. **Key vulnerability elements**:
   - Untrusted user input is directly concatenated into LDAP queries
   - No input validation or sanitization mechanisms are implemented
   - Special characters in LDAP queries are not properly escaped
   - The vulnerability bypasses input validation mechanisms inherent in OpenLDAP
   - Observed in Acme Corp's C++ LDAP authentication module running on Linux

2. **Potential attack vectors**:
   - Insertion of LDAP metacharacters to manipulate query structure
   - Authentication bypass through query manipulation
   - Unauthorized access to directory data beyond intended boundaries
   - Information disclosure of sensitive directory contents
   - Potential for unauthorized modification of directory data

3. **Severity assessment**:
   - The vulnerability enables unauthorized access to sensitive directory information
   - Both confidentiality and integrity are severely impacted
   - Availability is moderately affected through potential service disruption
   - Adjacent attack vector requiring network proximity or access
   - Low complexity exploitation requiring basic LDAP query knowledge

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): Low (L) 

# Description
A critical LDAP injection vulnerability exists in Acme Corp's C++ LDAP authentication module. The vulnerability occurs when untrusted user input is directly concatenated into LDAP distinguished names (DN) without proper escaping or sanitization.

```cpp
// Vulnerable code snippet
std::string ldapFilter = "(uid=" + userInput + ")";

```

This insecure practice allows attackers to insert LDAP metacharacters into the username field, thereby manipulating the structure and logic of LDAP queries. By crafting specific input values containing special characters, an attacker can alter query semantics, potentially bypassing authentication controls, accessing unauthorized data, or modifying directory information.

The vulnerability was discovered during code review and confirmed through dynamic testing on a Linux system running the OpenLDAP toolkit, demonstrating that an attacker can access directory information beyond their authorization level.

# CVSS
**Score**: 8.3 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L \
**Severity**: High

The High severity rating (8.3) reflects the significant security impact of this LDAP injection vulnerability:

- **Adjacent (A) attack vector**: The vulnerability requires network access to the authentication interface from a logically adjacent network, such as the internal network where the LDAP service is deployed. The attack cannot be executed from arbitrary remote networks but requires positioning within the relevant network segment.

- **Low (L) attack complexity**: Once an attacker has access to the input field, exploitation is straightforward and requires only basic knowledge of LDAP query syntax and injection techniques.

- **No privileges required (N)**: An attacker doesn't need any special privileges to exploit this vulnerability, as it affects the authentication mechanism itself.

- **No user interaction (N)**: The vulnerability can be exploited without requiring actions from legitimate users or administrators.

- **Unchanged scope (S)**: The impact is contained within the vulnerable LDAP authentication component.

- **High confidentiality impact (H)**: An attacker can potentially access sensitive information within the LDAP directory, including user credentials and other restricted data.

- **High integrity impact (H)**: Depending on the permissions of the LDAP service account, an attacker might be able to modify directory data, compromising the integrity of authentication information.

- **Low availability impact (L)**: While the primary impact is on confidentiality and integrity, there's potential for limited disruption to authentication services.

# Exploitation Scenarios
**Scenario 1: Authentication Bypass**
An attacker enters the following as username input: `* )(|(uid=*)`. This transforms the LDAP filter from `(uid=username)` into `(uid=* )(|(uid=*))`, which creates an always-true condition. This allows the attacker to authenticate as any user without knowing the correct password, effectively bypassing the authentication system entirely.

**Scenario 2: Information Disclosure**
An attacker inputs: `dummy)(objectClass=*)(|(objectClass=`. This modifies the LDAP query to return all objects in the directory regardless of their type, potentially exposing sensitive user information, group memberships, and organizational structures that should be restricted.

**Scenario 3: Directory Information Manipulation**
If the LDAP connection has write permissions, an attacker could craft input containing LDAP modify operations. For example, input containing specific LDAP operation codes could modify user attributes, change group memberships, or elevate privileges for certain accounts.

**Scenario 4: Denial of Service**
An attacker submits input containing wildcard characters and complex search filters designed to create resource-intensive queries. For example: `*)(|(objectClass=*)(objectClass=*)(objectClass=*)(objectClass=*)...`. This could cause the LDAP server to consume excessive CPU and memory resources, potentially leading to degraded performance or complete service unavailability.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive user credentials stored in the directory service
- Potential breach of confidential employee information and organizational structure
- Compromise of directory integrity leading to authentication and authorization failures
- Legal and regulatory compliance violations due to unauthorized data access
- Reputational damage if breach is discovered and publicly disclosed
- Business continuity issues if the vulnerability is exploited for denial of service
- Financial losses from breach remediation, investigation, and potential legal penalties

**Technical Impact:**
- Complete subversion of the authentication mechanism
- Unauthorized access to protected resources and services that rely on LDAP authentication
- Exposure of internal directory structure and configuration details
- Potential for credential harvesting and privilege escalation
- Lateral movement to other systems using stolen credentials
- Corruption of directory data affecting user management and access controls
- Persistent backdoor access through modified directory entries
- Loss of trust in the authentication infrastructure requiring full verification and potential rebuilding

# Technical Details
The vulnerability stems from directly incorporating user-supplied input into LDAP filter strings without applying proper sanitization or escaping mechanisms. Let's examine the vulnerable code in detail:

```cpp
#include <iostream>
#include <string>
#include <ldap.h>

int main() {
    // Simulated untrusted input from a user interface
    std::string userInput;
    std::cout << "Enter username: ";
    std::cin >> userInput;

    // Vulnerable LDAP filter construction: unescaped input directly inserted
    std::string ldapFilter = "(uid=" + userInput + ")";

    LDAP* ld;
    int result = ldap_initialize(&ld, "ldap://localhost");
    if (result != LDAP_SUCCESS) {
        std::cerr << "LDAP initialization failed: " 
                  << ldap_err2string(result) << std::endl;
        return 1;
    }

    // Perform an LDAP search using the vulnerable filter
    LDAPMessage* searchResult = nullptr;
    result = ldap_search_s(ld, "dc=acme,dc=corp", LDAP_SCOPE_SUBTREE,
                           ldapFilter.c_str(), nullptr, 0, &searchResult);
    
    if (result != LDAP_SUCCESS) {
        std::cerr << "LDAP search failed: " 
                  << ldap_err2string(result) << std::endl;
    } else {
        std::cout << "LDAP search executed with filter: "
                  << ldapFilter << std::endl;
    }

    ldap_msgfree(searchResult);
    ldap_unbind_ext(ld, nullptr, nullptr);
    return 0;
}

```

**Vulnerability Analysis:**

1. **The core issue** is at line 11 where user input is directly concatenated into the LDAP filter without any sanitization:
   ```cpp
   std::string ldapFilter = "(uid=" + userInput + ")";
   
   ```

2. **LDAP Query Syntax**: LDAP filters use a specific syntax with special characters that have meaning within queries:
   - Parentheses `()` define the scope of filters
   - Operators like `&` (AND), `|` (OR), and `!` (NOT) control logical operations
   - Equality operators (`=`, `>=`, `<=`) compare attributes to values
   - Wildcard character `*` matches any sequence of characters

3. **Exploitation Mechanics**: By injecting special characters, an attacker can:
   - Close the current filter prematurely with a closing parenthesis `)`
   - Introduce new logical operators
   - Add new filter conditions
   - Create always-true conditions

4. **Example Attack Inputs:**
   - `*` - Simple wildcard that matches any username
   - `*)(|(objectClass=*)` - Creates an always-true condition
   - `dummy)(cn=admin` - Attempts to search for admin accounts
   - `user)(uid=admin)(|(uid=` - Targets a specific high-privilege account

5. **Technical Context:**
   - The vulnerability exists in a Linux environment running OpenLDAP
   - The C++ code uses the standard LDAP C API via the `ldap.h` header
   - The search is performed with `LDAP_SCOPE_SUBTREE` which searches the entire directory tree under the base DN
   - No authorization limiting is implemented within the search parameters

# Remediation Steps
## Implement Proper LDAP Input Sanitization

**Priority**: P0

Modify the code to properly escape all special characters in user input before constructing LDAP filters:

```cpp
#include <iostream>
#include <string>
#include <ldap.h>

// Function to escape LDAP special characters in filter strings
std::string ldapEscapeFilter(const std::string& input) {
    std::string result;
    result.reserve(input.size() * 2); // Reserve space for potential escaping
    
    for (char c : input) {
        switch (c) {
            case '*':
                result += "\\2A"; // Escape asterisk
                break;
            case '(':
                result += "\\28"; // Escape left parenthesis
                break;
            case ')':
                result += "\\29"; // Escape right parenthesis
                break;
            case '\\':
                result += "\\5C"; // Escape backslash
                break;
            case '\0':
                result += "\\00"; // Escape NUL
                break;
            case '/':
                result += "\\2F"; // Escape forward slash
                break;
            default:
                result += c; // No escaping needed
        }
    }
    
    return result;
}

int main() {
    // Get user input
    std::string userInput;
    std::cout << "Enter username: ";
    std::cin >> userInput;
    
    // Properly escape the user input before constructing the filter
    std::string escapedInput = ldapEscapeFilter(userInput);
    std::string ldapFilter = "(uid=" + escapedInput + ")";
    
    // Rest of the LDAP search code remains unchanged
    // ...
}

```

This approach ensures that any special characters in the user input are properly escaped according to LDAP filter syntax rules, preventing injection attacks.
## Implement Input Validation and Parameterized Queries

**Priority**: P1

Enhance security by implementing strict input validation and using safer LDAP query construction techniques:

```cpp
#include <iostream>
#include <string>
#include <ldap.h>
#include <regex>

bool validateUsername(const std::string& username) {
    // Define a strict pattern for valid usernames (e.g., alphanumeric + limited symbols)
    std::regex validPattern("^[a-zA-Z0-9._-]{3,32}$");
    return std::regex_match(username, validPattern);
}

int performLdapSearch(LDAP* ld, const std::string& baseDN, const std::string& username) {
    // Use the OpenLDAP filter escaping function for extra safety
    char* escapedUsername = ldap_escape_filter(ld, username.c_str(), username.length());
    if (!escapedUsername) {
        std::cerr << "Failed to escape LDAP filter" << std::endl;
        return LDAP_PARAM_ERROR;
    }
    
    // Construct safer LDAP filter using the escaped value
    std::string ldapFilter = "(uid=" + std::string(escapedUsername) + ")";
    ldap_memfree(escapedUsername); // Free the memory allocated by ldap_escape_filter
    
    // Perform the LDAP search
    LDAPMessage* searchResult = nullptr;
    int result = ldap_search_s(ld, baseDN.c_str(), LDAP_SCOPE_SUBTREE,
                              ldapFilter.c_str(), nullptr, 0, &searchResult);
    
    if (result != LDAP_SUCCESS) {
        std::cerr << "LDAP search failed: " << ldap_err2string(result) << std::endl;
    } else {
        std::cout << "LDAP search executed with filter: " << ldapFilter << std::endl;
        ldap_msgfree(searchResult);
    }
    
    return result;
}

int main() {
    // Get user input
    std::string userInput;
    std::cout << "Enter username: ";
    std::cin >> userInput;
    
    // Validate the username format before proceeding
    if (!validateUsername(userInput)) {
        std::cerr << "Invalid username format. Please use only alphanumeric characters, dots, underscores, or hyphens." << std::endl;
        return 1;
    }
    
    // Initialize LDAP connection
    LDAP* ld;
    int result = ldap_initialize(&ld, "ldap://localhost");
    if (result != LDAP_SUCCESS) {
        std::cerr << "LDAP initialization failed: " << ldap_err2string(result) << std::endl;
        return 1;
    }
    
    // Perform the LDAP search with validated and escaped input
    result = performLdapSearch(ld, "dc=acme,dc=corp", userInput);
    
    // Clean up resources
    ldap_unbind_ext(ld, nullptr, nullptr);
    return (result == LDAP_SUCCESS) ? 0 : 1;
}

```

This implementation adds multiple layers of protection:
1. Input validation using a regular expression to enforce a strict username format
2. Utilization of OpenLDAP's built-in filter escaping function for proper handling of special characters
3. Separation of concerns with dedicated functions for validation and LDAP operations
4. Proper resource management and error handling


# References
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-77 | [Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* CWE-90 | [Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
