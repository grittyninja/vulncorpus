# Buffer Overflow via Insecure scanf() Usage

# Vulnerability Case
During the code review of Acme Corp's legacy C-based user management module, a buffer overflow vulnerability was identified in the input handling routine. The function responsible for capturing user data employs the insecure format specifier with `scanf()` without specifying a maximum field width, leaving the fixed-size buffer unprotected against oversized inputs. This vulnerability was observed in a real-world Linux application compiled with GCC, where standard C libraries are in use. The insecure use of `scanf()` was discovered during dynamic testing as part of a broader vulnerability assessment focused on input validation. Exploitation via this flaw may allow an attacker to overwrite adjacent memory regions, potentially hijacking program execution flow and impacting system availability and data integrity.

```c
#include <stdio.h>

int main(void) {
    char username[20];

    printf("Enter username: ");
    // Vulnerable usage: no field width limit in scanf() potentially leads to buffer overflow
    scanf("%s", username);
    
    printf("Welcome, %s", username);
    return 0;
}
```

The vulnerability stems from the use of `scanf()` with the `%s` format specifier without a length-limiting parameter, which does not account for the buffer boundary defined by the 20-byte `username` array. An attacker can supply input exceeding 19 characters (plus a null terminator), which may overwrite adjacent memory on the stack, leading to arbitrary code execution or denial of service. In a real-world scenario involving C applications on a Linux platform, such a flaw can be exploited to compromise service integrity, escalate privileges, or disrupt business operations.

context: c.lang.security.insecure-use-scanf-fn.insecure-use-scanf-fn Avoid using 'scanf()'. This function, when used improperly, does not consider buffer boundaries and can lead to buffer overflows. Use 'fgets()' instead for reading input.

# Vulnerability Breakdown
This vulnerability involves a classic buffer overflow issue caused by using the scanf() function without proper bounds checking.

1. **Key vulnerability elements**:
   - Fixed-size buffer of 20 bytes for username
   - Using scanf() with %s format specifier without field width limitation
   - No input validation or bounds checking
   - Stack-based buffer that can be overflowed with excessive input

2. **Potential attack vectors**:
   - Supplying input exceeding 19 characters (plus null terminator)
   - Crafting input to overwrite adjacent stack memory
   - Targeting the return address to control program execution flow
   - Injecting shellcode to achieve arbitrary code execution

3. **Severity assessment**:
   - Local attack vector requires access to the application
   - Low complexity exploitation requiring basic skills
   - No privileges required to execute the attack
   - High impact across confidentiality, integrity, and availability
   - Potential for arbitrary code execution or denial of service

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Local (L) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

CVSS Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

# Description
A buffer overflow vulnerability exists in Acme Corp's legacy C-based user management module due to the insecure use of the `scanf()` function without proper bounds checking. The code allocates a fixed-size buffer of 20 bytes for storing a username but fails to limit the input length when reading user data:

```c
#include <stdio.h>

int main(void) {
    char username[20];

    printf("Enter username: ");
    // Vulnerable usage: no field width limit in scanf() potentially leads to buffer overflow
    scanf("%s", username);
    
    printf("Welcome, %s", username);
    return 0;
}

```

This vulnerability allows an attacker to provide input exceeding the buffer's capacity (19 characters plus the null terminator), potentially overwriting adjacent memory on the stack. In a real-world scenario, this could lead to arbitrary code execution, privilege escalation, or service disruption, posing a significant security risk to the system and business operations.

# CVSS
**Score**: 8.4 \
**Vector**: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H \
**Severity**: High

The High severity rating is justified by the following factors:

- **Local attack vector (AV:L)**: The vulnerability requires local access to the affected system or application.

- **Low attack complexity (AC:L)**: Exploiting the vulnerability is straightforward and requires minimal expertise - simply providing input that exceeds the buffer size.

- **No privileges required (PR:N)**: The attacker doesn't need any special privileges to exploit the vulnerability; they only need to be able to run the vulnerable application.

- **No user interaction required (UI:N)**: Once the attacker has access to the application, they can directly exploit the vulnerability without requiring actions from other users.

- **Unchanged scope (S:U)**: The vulnerability affects only the vulnerable component without crossing security boundaries.

- **High confidentiality impact (C:H)**: Successfully exploiting this vulnerability could allow an attacker to access sensitive information by executing arbitrary code or reading protected memory.

- **High integrity impact (I:H)**: An attacker could modify data or system files by gaining control of the execution flow.

- **High availability impact (A:H)**: The vulnerability could be exploited to crash the application or cause a denial of service.

The combination of these factors results in a CVSS score of 8.4, which falls within the High severity range (7.0-8.9).

# Exploitation Scenarios
**Scenario 1: Stack Overflow Attack**
An attacker provides a carefully crafted username longer than 20 bytes, overwriting the return address on the stack. When the function returns, execution jumps to attacker-controlled code, potentially executing arbitrary commands with the privileges of the running application. For example, an input of 30+ characters with embedded machine code could lead to full system compromise.

**Scenario 2: Denial of Service**
An attacker submits an excessively long username that corrupts the stack memory in a way that causes the application to crash when attempting to return from the function. In a production environment, this could disrupt business operations, especially if the vulnerable code exists in a critical service running with elevated privileges.

**Scenario 3: Information Disclosure**
By carefully controlling the overflow, an attacker might be able to manipulate the stack in a way that causes the application to print memory contents beyond the intended buffer. This could potentially reveal sensitive information such as other variables, memory addresses, or system configuration details that help in constructing more sophisticated attacks.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to sensitive customer or business data
- Service disruption affecting business continuity
- Damage to company reputation if a breach occurs
- Regulatory compliance violations and potential fines
- Costs associated with incident response and recovery
- Loss of intellectual property if the system stores or processes proprietary information

**Technical Impact:**
- Arbitrary code execution with the permissions of the vulnerable application
- Potential privilege escalation if the application runs with elevated privileges
- System instability or crashes leading to service outages
- Possible lateral movement within the network if the compromised application has access to other systems
- Information disclosure through memory leaks
- Complete system compromise potentially requiring reinstallation
- Data corruption affecting system integrity

# Technical Details
The vulnerability exists in the use of `scanf()` with the `%s` format specifier without specifying a maximum field width. This is a classic buffer overflow vulnerability in C programming.

```c
#include <stdio.h>

int main(void) {
    char username[20];

    printf("Enter username: ");
    // Vulnerable usage: no field width limit in scanf() potentially leads to buffer overflow
    scanf("%s", username);
    
    printf("Welcome, %s", username);
    return 0;
}

```

**Memory Layout and Exploitation:**

In a typical stack layout, the local variables (like our `username` buffer) are allocated on the stack, followed by the saved frame pointer and the return address. When `scanf()` reads input without bounds checking, it continues writing beyond the allocated buffer if the input exceeds 19 characters (plus the null terminator).

Typical stack memory layout (growing downward):
```
Lower memory addresses
+-------------------------+
| Other stack variables   |
+-------------------------+
| username buffer (20B)   | <-- Buffer overflow starts here
+-------------------------+
| Saved Frame Pointer     | <-- Can be overwritten
+-------------------------+
| Return Address          | <-- Primary target for exploitation
+-------------------------+
| Function parameters     |
+-------------------------+
Higher memory addresses

```

When an attacker provides more than 19 characters:
1. The first 19 characters and null terminator fill the buffer (20 bytes)
2. Additional characters overflow into adjacent memory
3. If enough characters are provided, the return address can be overwritten
4. When the function returns, execution jumps to the address specified by the attacker

This is particularly dangerous in real-world applications where:
- The program might run with elevated privileges
- The vulnerability might exist in a network-facing service
- Modern exploitation techniques like Return-Oriented Programming (ROP) can bypass common protections

Even with protections like ASLR, stack canaries, or DEP, determined attackers might find ways to exploit this vulnerability through techniques like brute forcing, information leaks, or ROP chains.

# Remediation Steps
## Replace scanf() with Bounds-Checked Alternatives

**Priority**: P0

Replace the unsafe `scanf()` call with a bounds-checked alternative:

```c
// Option 1: Use scanf() with field width limiter
printf("Enter username: ");
scanf("%19s", username);  // Limit to 19 chars + null terminator

// Option 2: Use fgets() (preferred)
printf("Enter username: ");
fgets(username, sizeof(username), stdin);
// Remove newline character if present
size_t len = strlen(username);
if (len > 0 && username[len-1] == '\n') {
    username[len-1] = '\0';
}

```

The first option adds a field width specifier (19) to the format string, which limits the number of characters `scanf()` will read. The second option uses `fgets()`, which takes a size parameter explicitly limiting the number of bytes read, making it the safer choice. In both cases, these changes ensure the input cannot exceed the buffer's capacity.
## Implement Comprehensive Input Validation

**Priority**: P1

Add input validation to ensure that user input meets expected requirements:

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int is_valid_username(const char* username) {
    size_t len = strlen(username);
    
    // Check length (e.g., between 3 and 15 characters)
    if (len < 3 || len > 15) {
        return 0;
    }
    
    // Check character set (e.g., alphanumeric and underscores only)
    for (size_t i = 0; i < len; i++) {
        if (!isalnum(username[i]) && username[i] != '_') {
            return 0;
        }
    }
    
    return 1;
}

int main(void) {
    char username[20];
    
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    
    // Remove newline if present
    size_t len = strlen(username);
    if (len > 0 && username[len-1] == '\n') {
        username[len-1] = '\0';
    }
    
    // Validate input
    if (!is_valid_username(username)) {
        printf("Invalid username. Please use 3-15 alphanumeric characters or underscores.\n");
        return 1;
    }
    
    printf("Welcome, %s\n", username);
    return 0;
}

```

This implementation adds:
1. Length validation to ensure usernames fall within acceptable bounds
2. Character set validation to ensure only allowed characters are used
3. Proper error handling and user feedback

Implementing these checks adds defense-in-depth by rejecting potentially malicious input before it can be processed.


# References
* CWE-787 | [Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-121 | [Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
