# Insecure Deserialization Using BinaryFormatter

# Vulnerability Case
During our assessment of Acme Corp’s legacy .NET application, we discovered that data received over a public API endpoint is deserialized using the insecure `BinaryFormatter` without proper validation. The vulnerability was identified during a code audit of the Windows service that processes incoming binary data streams. This insecure deserialization exposes the application to attacks where an adversary could supply a crafted payload, leading to arbitrary code execution and privilege escalation on the backend server hosting the .NET Framework 4.7 environment on Azure.

```csharp
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace InsecureDeserializationDemo
{
    [Serializable]
    public class DataObject
    {
        public string Data { get; set; }
    }

    public class DeserializationService
    {
        public DataObject ProcessReceivedData(byte[] serializedData)
        {
            // Vulnerable pattern: Insecure deserialization using BinaryFormatter
            BinaryFormatter formatter = new BinaryFormatter();
            using (MemoryStream stream = new MemoryStream(serializedData))
            {
                // Deserialize untrusted binary data without type validation
                return (DataObject)formatter.Deserialize(stream);
            }
        }
    }
}
```

The insecure use of `BinaryFormatter` allows an attacker to inject a malicious payload that, when deserialized, can instantiate objects with unexpected behavior—potentially triggering methods like those in `IDeserializationCallback` or exploiting the object’s constructor logic. This exploitation could lead to remote code execution on the affected host, posing critical business risks such as unauthorized system access, data leakage, and disruption of service.

context: csharp.lang.security.insecure-deserialization.binary-formatter.insecure-binaryformatter-deserialization The BinaryFormatter type is dangerous and is not recommended for data processing. Applications should stop using BinaryFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. BinaryFormatter is insecure and can't be made secure

# Vulnerability Breakdown
This vulnerability involves insecure deserialization of untrusted data in a legacy .NET application, enabling potential remote code execution.

1. **Key vulnerability elements**:
   - Use of dangerous `BinaryFormatter` class to deserialize untrusted input
   - No type validation or sanitization of incoming serialized data
   - Public API endpoint exposing the vulnerable functionality
   - Serializable classes that could be manipulated by attackers
   - Windows service processing potentially malicious binary data streams

2. **Potential attack vectors**:
   - Crafting malicious serialized objects with unexpected types
   - Exploiting serialization callbacks like `IDeserializationCallback`
   - Leveraging gadget chains within the .NET Framework
   - Targeting constructor logic of deserialized objects
   - Utilizing Type/Assembly loading capabilities during deserialization

3. **Severity assessment**:
   - Remote code execution capability with high impact
   - Network-accessible vulnerability through public API
   - High attack complexity requiring specialized knowledge of .NET serialization
   - No authentication required to exploit
   - No user interaction needed to trigger the vulnerability
   - Complete system compromise possible

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

# Description
A critical vulnerability exists in Acme Corp's legacy .NET application where a public API endpoint deserializes data using the insecure `BinaryFormatter` class without proper validation. This Windows service, which processes incoming binary data streams running on .NET Framework 4.7 in an Azure environment, fails to validate the types being deserialized, allowing attackers to supply crafted payloads leading to remote code execution.

```csharp
public DataObject ProcessReceivedData(byte[] serializedData)
{
    // Vulnerable pattern: Insecure deserialization using BinaryFormatter
    BinaryFormatter formatter = new BinaryFormatter();
    using (MemoryStream stream = new MemoryStream(serializedData))
    {
        // Deserialize untrusted binary data without type validation
        return (DataObject)formatter.Deserialize(stream);
    }
}

```

The vulnerability arises because `BinaryFormatter` deserializes data in a way that can instantiate arbitrary .NET types and invoke methods during the deserialization process, including constructors, property setters, and serialization callbacks, which can lead to arbitrary code execution. Microsoft has explicitly warned against using BinaryFormatter for processing any data, even data believed to be trusted.

# CVSS
**Score**: 8.1 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H \
**Severity**: High

The High severity rating (8.1) is justified by the following factors:

- **Network (N) attack vector**: The vulnerability is exploitable remotely over the internet via a public API endpoint, significantly increasing the potential attacker pool
- **High (H) attack complexity**: Successful exploitation requires deep knowledge of .NET serialization internals, gadget chains available in the specific environment, and careful crafting of binary payloads. The attacker must understand the application's type structure and identify suitable gadget chains, which may require significant research and multiple attempts.
- **No privileges (N) required**: No authentication or special privileges are needed to exploit the vulnerability
- **No user interaction (UI) required**: The attack can be fully automated without any actions from users or administrators
- **Unchanged (U) scope**: While the impact is severe, it's limited to the application and its environment
- **High (H) impact on confidentiality**: Successful exploitation allows attackers to read sensitive application data, potentially including credentials or personal information
- **High (H) impact on integrity**: Remote code execution enables attackers to modify data or inject malicious functionality
- **High (H) impact on availability**: Attacks can cause the application to crash or become unavailable

Though the attack complexity is high, the critical nature of the vulnerability, combined with its network accessibility and high impact across all three security areas, results in a high severity score of 8.1.

# Exploitation Scenarios
**Scenario 1: Remote Code Execution via Gadget Chain**
An attacker analyzes the application's dependencies and identifies a known deserialization gadget chain available in the .NET Framework or application libraries. The attacker crafts a serialized payload that, when deserialized by BinaryFormatter, triggers method calls that ultimately execute arbitrary code. For example, using the YSoSerial.NET tool, the attacker generates a malicious BinaryFormatter payload targeting a gadget chain in a common library, submits it to the API endpoint, and achieves code execution with the privileges of the application service account.

```csharp
// Example of how an attacker might create a malicious payload using YSoSerial.NET
// ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "calc.exe"
// The resulting base64 string is sent to the vulnerable API

```

**Scenario 2: Data Extraction Through File Access**
An attacker creates a serialized object that, when deserialized, reads sensitive files from the server's filesystem and transmits their contents back to the attacker. This could be accomplished by using serialization callbacks or constructors that read files and exfiltrate data using outbound HTTP requests or DNS queries, effectively bypassing network-level data exfiltration controls.

**Scenario 3: Persistent Backdoor Installation**
An attacker exploits the vulnerability to execute code that creates a scheduled task, registry autorun entry, or Windows service that provides persistent access to the server. This backdoor runs with the same privileges as the vulnerable application, allowing the attacker to maintain access even if the original vulnerability is later patched.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive business data and intellectual property
- Potential breach of customer personally identifiable information (PII)
- Regulatory compliance violations and potential fines (GDPR, HIPAA, etc.)
- Reputational damage from public disclosure of a breach
- Service disruption and operational impact if systems are compromised
- Financial losses from breach response, investigation, and remediation
- Possible legal liability if customer data is exposed

**Technical Impact:**
- Complete compromise of the application and host system
- Lateral movement potential within the Azure environment
- Unauthorized access to connected databases and storage
- Data exfiltration capabilities through the compromised service
- Injection of malicious code into the application
- Potential for persistent access mechanisms (backdoors)
- Access to application secrets and configuration data
- Denial of service by crashing the application
- Potential for pivot attacks against other internal systems

# Technical Details
The vulnerability stems from using the `BinaryFormatter` class to deserialize untrusted data coming from a public API. BinaryFormatter is particularly dangerous because:

1. **Type instantiation**: It can create any type available in the application's loaded assemblies or the GAC
2. **Code execution hooks**: Several mechanisms during deserialization can trigger code execution:
   - Constructor calls
   - Property setters and getters
   - Deserialization callbacks (IDeserializationCallback.OnDeserialization)
   - SerializationBinder implementations
   - TypeConverters
   - IObjectReference.GetRealObject

The vulnerable code pattern is:

```csharp
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace InsecureDeserializationDemo
{
    [Serializable]
    public class DataObject
    {
        public string Data { get; set; }
    }

    public class DeserializationService
    {
        public DataObject ProcessReceivedData(byte[] serializedData)
        {
            // Vulnerable pattern: Insecure deserialization using BinaryFormatter
            BinaryFormatter formatter = new BinaryFormatter();
            using (MemoryStream stream = new MemoryStream(serializedData))
            {
                // Deserialize untrusted binary data without type validation
                return (DataObject)formatter.Deserialize(stream);
            }
        }
    }
}

```

**Exploitation mechanics:**

1. During deserialization, BinaryFormatter processes the serialized data stream, which includes:
   - Type information (assembly and class names)
   - Object graph data
   - References to other objects

2. An attacker can craft a serialized stream containing types that weren't intended by the application developers

3. When BinaryFormatter encounters these types during deserialization, it:
   - Loads the specified assembly
   - Creates instances of the malicious types
   - Populates object properties
   - Invokes deserialization callbacks

4. Through carefully constructed object graphs (gadget chains), attackers can chain method calls to achieve code execution

**Tools like YSoSerial.NET automate the creation of malicious payloads targeting known gadget chains in common .NET libraries.**

This vulnerability has been extensively documented by Microsoft, who now strongly recommends against using BinaryFormatter in any context due to its inherent security risks. Even with attempts to secure it (via SerializationBinder or filtering), the complexity of the .NET serialization system makes it practically impossible to use BinaryFormatter securely.

# Remediation Steps
## Replace BinaryFormatter with a Safer Alternative

**Priority**: P0

Replace BinaryFormatter with a safer serialization alternative that doesn't instantiate arbitrary types:

```csharp
using System.Text.Json;
using System.IO;

public DataObject ProcessReceivedData(byte[] serializedData)
{
    // Convert the binary data to a string if necessary
    string jsonData = System.Text.Encoding.UTF8.GetString(serializedData);
    
    // Use System.Text.Json (built into modern .NET) to deserialize safely
    var options = new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true
    };
    
    return JsonSerializer.Deserialize<DataObject>(jsonData, options);
}

```

Alternatively, for .NET Framework applications:

```csharp
using Newtonsoft.Json;
using System.IO;

public DataObject ProcessReceivedData(byte[] serializedData)
{
    // Convert the binary data to a string
    string jsonData = System.Text.Encoding.UTF8.GetString(serializedData);
    
    // Use JSON.NET to deserialize safely
    JsonSerializerSettings settings = new JsonSerializerSettings
    {
        TypeNameHandling = TypeNameHandling.None  // Critical security setting - disables type information
    };
    
    return JsonConvert.DeserializeObject<DataObject>(jsonData, settings);
}

```

These implementations:
1. Use JSON instead of binary serialization
2. Explicitly specify the expected type (DataObject)
3. Disable type information in the JSON to prevent type-based attacks
4. Are resistant to most deserialization attacks
## Implement Input Validation and API Contracts

**Priority**: P1

Add strong input validation before deserialization and define explicit API contracts:

```csharp
using System.Text.Json;
using System.IO;
using System.Text.RegularExpressions;

public class ApiInputValidator
{
    // Define validation rules for your data model
    public static bool IsValidDataObject(string jsonData)
    {
        try {
            // Check if the JSON is well-formed
            using (JsonDocument doc = JsonDocument.Parse(jsonData))
            {
                // Validate object has expected structure
                JsonElement root = doc.RootElement;
                
                // Ensure the Data property exists and is a string
                if (!root.TryGetProperty("Data", out JsonElement dataProperty) || 
                    dataProperty.ValueKind != JsonValueKind.String)
                {
                    return false;
                }
                
                // Apply specific validation rules to the Data property
                string data = dataProperty.GetString();
                if (string.IsNullOrEmpty(data) || data.Length > 1000)
                {
                    return false;
                }
                
                // Check for potentially dangerous content
                if (Regex.IsMatch(data, @"<script>|javascript:|\\u0022|eval\\(|document\\.cookie"))
                {
                    return false;
                }
                
                return true;
            }
        }
        catch {
            return false;
        }
    }
}

public DataObject ProcessReceivedData(byte[] serializedData)
{
    // Convert binary data to string
    string jsonData = System.Text.Encoding.UTF8.GetString(serializedData);
    
    // Validate the input before deserialization
    if (!ApiInputValidator.IsValidDataObject(jsonData))
    {
        throw new ArgumentException("Invalid input data format");
    }
    
    // Now deserialize the validated data
    return JsonSerializer.Deserialize<DataObject>(jsonData);
}

```

This implementation:
1. Validates the JSON data is well-formed
2. Ensures the expected properties exist with the correct types
3. Applies business validation rules to each property
4. Checks for potentially malicious content patterns
5. Only deserializes data that passes all validation checks


# References
* CWE-502 | [Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* A08:2021 | [Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
* CWE-94 | [Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
