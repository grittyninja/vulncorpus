# Format String Injection in C++ Microservice

# Vulnerability Case
During our assessment of Acme Corp's C++ microservice handling user-supplied log messages via RESTful APIs, we discovered a format string injection vulnerability. The flaw was identified when reviewing the logging subsystem, where externally controlled data was directly used as the format string in calls to standard I/O functions. This pattern, observed in a GNU C++ environment leveraging glibc on Linux, allows an attacker to inject format specifiers, potentially leaking sensitive memory content or triggering memory corruption. The vulnerability was confirmed through careful code inspection and runtime tests that manipulated the input to reveal unintended memory disclosures. Such weaknesses may lead to Denial of Service (DoS) or escalate into arbitrary code execution under specific conditions.

```cpp
#include <cstdio>
#include <cstring>

void logEvent(const char* userInput) {
    char logBuffer[512];
    // Vulnerable: the user-controlled input is directly used as the format string.
    snprintf(logBuffer, sizeof(logBuffer), userInput);
    printf("Event logged: %s", logBuffer);
}

int main() {
    // Simulated user input that could include malicious format specifiers.
    const char* maliciousInput = "%x %x %x %x";
    logEvent(maliciousInput);
    return 0;
}
```

The vulnerability arises from using an externally controlled string as the format string in functions like `snprintf`, which expects a constant string with format specifiers. An attacker can supply malicious format specifiers (e.g., `%x`, `%s` ) to read arbitrary memory locations, leading to potential disclosure of sensitive runtime data. In more advanced exploitation, such malformed inputs might manipulate stack data and trigger memory corruption, providing a foothold for DoS attacks or even arbitrary code execution. This security flaw poses a significant business impact by possibly exposing confidential data and destabilizing critical services within Acme Corp's infrastructure.

context: cpp.lang.security.format-string.format-string-injection.format-string-injection Externally controlled data influences a format string. This can allow an attacker to leak information from memory or trigger memory corruption. Format strings should be constant strings to prevent these issues. If you need to print a user-controlled string then you can use `%s`.

# Vulnerability Breakdown
This vulnerability involves a classic format string injection in a C++ microservice where user-controlled data is directly used as the format string parameter in stdio functions.

1. **Key vulnerability elements**:
   - User-supplied input is directly used as a format string parameter to `snprintf()`
   - No validation or sanitization of user input before usage
   - Logging subsystem exposed via RESTful APIs
   - Running in a GNU C++ environment with glibc on Linux

2. **Potential attack vectors**:
   - Injecting format specifiers like `%x`, `%p` to read arbitrary memory
   - Using `%n` format specifier to potentially write to memory locations
   - Manipulating input to cause memory corruption or undefined behavior
   - Chaining with other vulnerabilities for more sophisticated attacks

3. **Severity assessment**:
   - High confidentiality impact due to potential disclosure of sensitive memory contents
   - High integrity impact as format string vulnerabilities could allow memory corruption
   - High availability impact from potential crashes or service disruption
   - Network exploitable through RESTful API
   - Low complexity exploitation requiring basic understanding of format string vulnerabilities

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
A format string injection vulnerability exists in Acme Corp's C++ microservice that handles user-supplied log messages via RESTful APIs. The vulnerability occurs in the logging subsystem where user-controlled input is directly passed as the format string parameter to `snprintf()` without proper validation or sanitization.

```cpp
#include <cstdio>
#include <cstring>

void logEvent(const char* userInput) {
    char logBuffer[512];
    // Vulnerable: the user-controlled input is directly used as the format string.
    snprintf(logBuffer, sizeof(logBuffer), userInput);
    printf("Event logged: %s", logBuffer);
}

```

This vulnerability allows attackers to inject format specifiers (such as `%x`, `%s`, `%n`) that can leak sensitive information from memory or potentially cause memory corruption. Since the microservice processes input via RESTful APIs, this vulnerability can be exploited remotely, posing a significant security risk to Acme Corp's infrastructure.

# CVSS
**Score**: 9.8 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H \
**Severity**: Critical

The Critical severity rating is justified by the following factors:

- **Network attack vector (AV:N)**: The vulnerability is remotely exploitable via the RESTful API interface, allowing attackers to access it from anywhere with network connectivity.

- **Low attack complexity (AC:L)**: Exploiting format string vulnerabilities is well-understood and requires only basic knowledge of format specifiers. Creating a malicious payload does not require special conditions or extensive preparation.

- **No privileges required (PR:N)**: No authentication or authorization is needed to exploit the vulnerability, as the service processes user-supplied log messages directly.

- **No user interaction required (UI:N)**: The attack can be performed entirely by the attacker with no need for user actions.

- **Unchanged scope (S:U)**: The vulnerability affects only the component where it exists, but that component handles user input and can access sensitive memory.

- **High confidentiality impact (C:H)**: Format string vulnerabilities can leak arbitrary memory contents, potentially exposing sensitive information like credentials, keys, or personal data.

- **High integrity impact (I:H)**: Advanced format string attacks using the `%n` specifier could potentially write to memory locations, corrupting application data or control flow.

- **High availability impact (A:H)**: Memory corruption can lead to application crashes, resulting in denial of service.

# Exploitation Scenarios
**Scenario 1: Information Disclosure via Format String Leak**
An attacker sends a log message containing multiple `%x` or `%p` format specifiers to the vulnerable API endpoint:

```
POST /api/log
Content-Type: application/json

{"message": "%x %x %x %x %x %x %x %x"}

```

When processed by the `logEvent` function, each `%x` causes `snprintf()` to interpret values on the stack as hexadecimal integers and include them in the output. The response or subsequent logs might contain something like:

```
Event logged: 7ffd3c45e710 0 7f2b5c83a700 7f2b5c83a700 1 18 7f2b5c79dff4 25

```

These values represent memory addresses and data that should not be accessible to users. The attacker analyzes these values to map the memory layout and potentially identify sensitive information like pointers, canaries, or application data.

**Scenario 2: Memory Corruption via %n Specifier**
In a more advanced attack, an attacker crafts a payload using the `%n` format specifier, which writes the number of characters printed so far to the provided address:

```
POST /api/log
Content-Type: application/json

{"message": "AAAAAAAA%134520836x%n"}

```

This payload might cause `snprintf()` to write a value to a memory address controlled by the attacker. If successful, this could overwrite critical application data, modify control flow, or even lead to arbitrary code execution in specific circumstances.

**Scenario 3: Denial of Service Attack**
An attacker sends a log message with a large number of format specifiers designed to cause excessive processing or crashes:

```
POST /api/log
Content-Type: application/json

{"message": "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"}

```

When processed, each `%s` tries to interpret a value on the stack as a pointer to a null-terminated string. If any of these pointers are invalid, the application will likely crash with a segmentation fault. Even if the application doesn't crash, processing extremely long format strings could consume significant CPU resources, potentially leading to service degradation.

# Impact Analysis
**Business Impact:**
- Potential exposure of sensitive customer data processed by the microservice
- Risk of regulatory compliance violations if personal or protected information is leaked
- Service disruptions affecting business operations if exploited for denial of service
- Potential breach of internal systems if attackers can leverage leaked information
- Reputational damage if vulnerability leads to a publicized security incident
- Financial impact from incident response, forensics, and remediation efforts

**Technical Impact:**
- Disclosure of sensitive memory contents including pointers, stack data, and potentially credentials
- Information about memory layout that could facilitate other attacks
- Potential memory corruption leading to unpredictable application behavior
- Service instability or crashes causing availability issues
- Possibility of arbitrary code execution in worst-case scenarios
- Potential for lateral movement if the compromised service has access to other internal systems
- Compromise of logging integrity, potentially masking further attacks

# Technical Details
The vulnerability exists in the logging subsystem of the C++ microservice which directly uses user-controlled input as the format string in `snprintf()`. Format string functions in C/C++ such as `printf()`, `sprintf()`, `snprintf()`, etc., interpret special format specifiers in the format string parameter.

```cpp
void logEvent(const char* userInput) {
    char logBuffer[512];
    // Vulnerable: the user-controlled input is directly used as the format string.
    snprintf(logBuffer, sizeof(logBuffer), userInput);
    printf("Event logged: %s", logBuffer);
}

int main() {
    // Simulated user input that could include malicious format specifiers.
    const char* maliciousInput = "%x %x %x %x";
    logEvent(maliciousInput);
    return 0;
}

```

The core issue is that format strings should be static, developer-controlled strings, not dynamic user input. When `userInput` contains format specifiers like `%x` or `%s`, these are interpreted as instructions to process additional arguments:

1. **Format Specifier Behavior:**
   - `%x`, `%d`, `%u`: Read an integer from the argument list or stack
   - `%s`: Read a pointer and interpret it as a string
   - `%n`: Write the number of characters output so far to the address provided as an argument

2. **Exploitation Mechanism:**
   When no corresponding arguments are provided (as in this case), the format function will read values from the stack, exposing memory contents. The `%n` specifier is particularly dangerous as it can write to memory.

3. **Platform-Specific Considerations:**
   In GNU C++ with glibc on Linux (the reported environment), format string vulnerabilities can be particularly effective due to:
   - Predictable stack layout
   - Minimal format string protections in older glibc versions
   - Ability to use direct parameter access in format strings (e.g., `%7$x` to access the 7th parameter)

4. **Exploitation Difficulty:**
   While basic information disclosure via `%x` or `%s` is relatively simple, achieving memory writes or code execution requires more sophisticated exploitation techniques:
   - Determining correct offsets in the stack
   - Bypassing modern memory protections (ASLR, DEP, stack canaries)
   - Crafting reliable payloads for the specific environment

5. **Detection Methods:**
   This vulnerability can be detected through:
   - Static code analysis identifying format strings sourced from user input
   - Dynamic testing with format string payloads
   - Code review practices that flag unsafe use of format functions

In this particular case, the vulnerability is exacerbated by the RESTful API interface, which makes it remotely exploitable rather than requiring local access.

# Remediation Steps
## Fix Format String Usage

**Priority**: P0

Immediately modify the vulnerable code to use a constant format string and pass user input as a parameter:

```cpp
void logEvent(const char* userInput) {
    char logBuffer[512];
    // Fixed: Using a constant format string with user input as parameter
    snprintf(logBuffer, sizeof(logBuffer), "%s", userInput);
    printf("Event logged: %s", logBuffer);
}

```

This change ensures that the format specifiers are controlled by the developer, not the user. The `%s` specifier safely treats the user input as a string parameter rather than interpreting it for format specifiers. This fix should be applied to all instances where user input might be used as a format string.
## Implement Input Validation and Sanitization

**Priority**: P1

Add input validation to reject or sanitize potentially dangerous input before processing:

```cpp
#include <cstdio>
#include <cstring>
#include <regex>
#include <string>

bool isValidLogMessage(const char* input) {
    // Check if input contains any format specifiers
    std::regex formatSpecifierPattern("%[0-9]*[diuoxXfFeEgGaAcspn]");
    std::string inputStr(input);
    
    // Return false if format specifiers are found
    if (std::regex_search(inputStr, formatSpecifierPattern)) {
        return false;
    }
    
    // Add additional validation rules as needed for your application
    // (e.g., length limits, character restrictions)
    
    return true;
}

void logEvent(const char* userInput) {
    // Validate input before processing
    if (!isValidLogMessage(userInput)) {
        fprintf(stderr, "Invalid log message rejected\n");
        return;
    }
    
    char logBuffer[512];
    // Even with validation, still use constant format string as defense in depth
    snprintf(logBuffer, sizeof(logBuffer), "%s", userInput);
    printf("Event logged: %s", logBuffer);
}

```

This approach provides an additional layer of protection by explicitly checking for and rejecting input containing format specifiers. The regex pattern searches for common format specifiers that could be used in an attack.


# References
* CWE-134 | [Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-787 | [Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
* CWE-125 | [Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
