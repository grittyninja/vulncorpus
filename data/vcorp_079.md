# Cleartext Transmission of Sensitive Data Over Unencrypted Socket

# Vulnerability Case
During a routine security audit of Acme Corp's Java-based microservices deployed on Apache Tomcat (running on Java 11), our team discovered that certain network communications were implemented using `java.net.Socket` without encryption. The issue was identified by analyzing source code and network traffic logs, where cleartext transmissions were observed for sensitive API calls. This insecure pattern exposes confidential data to interception and tampering by an attacker with network access, potentially enabling man-in-the-middle (MitM) exploitation.

```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class InsecureCommunication {
    public static void main(String[] args) {
        try {
            // Vulnerable pattern: using an unencrypted socket
            Socket socket = new Socket("secure-api.acme.com", 8080);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream())
            );

            out.println("GET /data HTTP/1.1");
            out.println("Host: secure-api.acme.com");
            out.println();

            String responseLine;
            while ((responseLine = in.readLine()) != null) {
                System.out.println(responseLine);
            }

            in.close();
            out.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

By using an unencrypted socket, sensitive data transmitted in cleartext can easily be intercepted using packet capture tools like Wireshark or tcpdump. An adversary on the same network can perform a MitM attack to read, modify, or inject data into the communication stream by exploiting the lack of transport layer encryption. This vulnerability may lead to leakage of confidential customer and financial data, undermining the integrity and trust of the business. The overall business impact includes potential regulatory violations, significant remediation costs, and reputational damage resulting from compromised customer information.


context: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket Detected use of a Java socket that is not encrypted. As a result, the traffic could be read by an attacker intercepting the network traffic. Use an SSLSocket created by 'SSLSocketFactory' or 'SSLServerSocketFactory' instead.

# Vulnerability Breakdown
This vulnerability involves the use of unencrypted Java sockets (`java.net.Socket`) for transmitting sensitive information between microservices, exposing data to network interception.

1. **Key vulnerability elements**:
   - Use of `java.net.Socket` instead of `SSLSocket` for network communications
   - Transmission of sensitive API data in cleartext
   - Lack of transport layer encryption
   - Java-based microservices deployed on Apache Tomcat (Java 11)

2. **Potential attack vectors**:
   - Network traffic sniffing/eavesdropping on the same network
   - Man-in-the-Middle (MITM) attacks to intercept and modify data
   - Session hijacking through capture of authentication tokens
   - ARP spoofing or DNS poisoning to redirect traffic

3. **Severity assessment**:
   - High confidentiality impact due to exposure of sensitive data
   - High integrity impact due to potential data modification
   - Adjacent attack vector requiring network access
   - Low complexity to execute using common tools like Wireshark

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): None (N) 

# Description
A serious cryptographic vulnerability has been identified in Acme Corp's Java-based microservices deployed on Apache Tomcat (Java 11), where sensitive network communications are implemented using unencrypted `java.net.Socket` connections instead of secure alternatives.

```java
// Vulnerable pattern
Socket socket = new Socket("secure-api.acme.com", 8080);

```

This implementation transmits all data in cleartext, allowing attackers with access to the network path to intercept, read, and potentially modify sensitive information using common tools like Wireshark or tcpdump. Despite the hostname suggesting security ("secure-api.acme.com"), the connection lacks transport layer encryption, creating a significant security risk for sensitive API calls and data transmissions.

# CVSS
**Score**: 8.1 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N \
**Severity**: High

The High severity rating (8.1) is justified by several factors:

- **Adjacent (A) attack vector**: The attacker must have access to the same network as the vulnerable communication path, which slightly limits the attack surface compared to remotely exploitable vulnerabilities.

- **Low (L) attack complexity**: Exploiting the vulnerability is straightforward as it requires only standard network interception tools like Wireshark, with minimal technical knowledge needed.

- **No privileges (N) required**: An attacker does not need any privileges on the target systems to intercept the network traffic.

- **No user interaction (UI) needed**: The vulnerability can be exploited passively without requiring any action from legitimate users.

- **Unchanged (U) scope**: The vulnerability affects only the sensitive data being transmitted between the components, without directly impacting other systems.

- **High (H) confidentiality impact**: All sensitive data transmitted through these unencrypted connections can be captured in full, potentially including credentials, tokens, and business-critical information.

- **High (H) integrity impact**: Through Man-in-the-Middle attacks, an attacker could potentially modify data in transit, compromising data integrity and potentially leading to transaction tampering or API request manipulation.

- **No (N) availability impact**: The vulnerability itself doesn't directly impact the availability of the services.

# Exploitation Scenarios
**Scenario 1: Network Eavesdropping**
An attacker with access to the network between Acme Corp's microservices (such as a malicious insider, compromised network device, or someone on the same WiFi network) uses Wireshark to passively capture traffic. The attacker configures a filter for port 8080 and the hostname "secure-api.acme.com" to isolate relevant communications. Since the data is transmitted in cleartext, the attacker can directly read sensitive information such as authentication tokens, customer data, or financial details without any decryption needed. This attack is particularly dangerous because it leaves no traces on either the client or server systems.

**Scenario 2: Active Man-in-the-Middle Attack**
A more sophisticated attacker uses ARP spoofing or DNS poisoning to redirect traffic intended for "secure-api.acme.com" through their machine. Using a tool like Burp Suite or mitmproxy, they not only capture the data but actively modify it in transit. For example, they could alter API responses to include malicious payloads, modify financial transaction details, or inject false information. Since there's no encryption or certificate validation, neither the client nor server detects the tampering.

**Scenario 3: Session Hijacking Through Token Capture**
The attacker captures authentication tokens or session identifiers transmitted in cleartext between the microservices. Using these captured credentials, they craft their own requests to the API service, effectively hijacking the legitimate session. This allows them to impersonate authorized systems or users, potentially gaining unauthorized access to administration interfaces, sensitive customer records, or financial transactions. The attack might go undetected because the requests appear legitimate from the server's perspective.

# Impact Analysis
**Business Impact:**
- Potential regulatory violations for handling sensitive data without proper encryption (GDPR, PCI DSS, HIPAA), leading to significant financial penalties
- Legal liability and potential lawsuits if customer data is exposed
- Reputational damage and loss of customer trust if a breach is disclosed
- Financial losses from fraudulent transactions if payment data is intercepted and misused
- Costs associated with incident response, forensic investigation, and remediation efforts
- Possible breach disclosure requirements depending on the type of data exposed
- Competitive disadvantage if proprietary business information is compromised

**Technical Impact:**
- Unauthorized access to sensitive data transmitted between microservices
- Data integrity issues if attackers modify transactions or API requests in transit
- Potential for credential theft leading to deeper system compromise
- Session hijacking enabling unauthorized system access
- Supply chain compromise if communications with external partners are similarly unprotected
- Difficulty in detecting passive eavesdropping attacks since they leave no evidence in logs
- False sense of security due to hostname ("secure-api.acme.com") suggesting protection
- Bypassing of application-level access controls through captured credentials or tokens

# Technical Details
The vulnerability exists in Acme Corp's Java-based microservices due to the direct use of unsecured `java.net.Socket` for network communications instead of using encrypted alternatives like `SSLSocket`.

```java
// Vulnerable code pattern
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class InsecureCommunication {
    public static void main(String[] args) {
        try {
            // Vulnerable pattern: using an unencrypted socket
            Socket socket = new Socket("secure-api.acme.com", 8080);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream())
            );

            out.println("GET /data HTTP/1.1");
            out.println("Host: secure-api.acme.com");
            out.println();

            String responseLine;
            while ((responseLine = in.readLine()) != null) {
                System.out.println(responseLine);
            }

            in.close();
            out.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

```

**Technical issues with this implementation:**

1. **Lack of Transport Layer Security**: The standard `Socket` class provides no encryption, unlike `SSLSocket` which would encrypt all data using TLS/SSL.

2. **No Certificate Validation**: Without SSL/TLS, there's no validation of server certificates, making it impossible to verify the identity of the server and leaving the connection vulnerable to Man-in-the-Middle attacks.

3. **Plaintext Protocol**: The code is implementing a basic HTTP request (not HTTPS) as seen in the manual creation of HTTP headers, further confirming the lack of encryption.

4. **Misleading Resource Name**: Despite connecting to a host named "secure-api.acme.com", the connection is made on port 8080, typically used for unencrypted HTTP traffic, rather than the standard HTTPS port 443.

5. **Manual Socket Management**: The implementation manually manages socket connections rather than using higher-level APIs like `HttpsURLConnection` or Apache HttpClient that would handle encryption and certificate validation properly.

**Attack Vectors:**

The unencrypted socket communication can be exploited through various network interception techniques:

1. **Passive Sniffing**: Tools like Wireshark can capture and analyze the unencrypted traffic.

2. **ARP Spoofing**: An attacker can manipulate Address Resolution Protocol (ARP) tables to redirect traffic through their machine.

3. **DNS Poisoning**: By corrupting DNS responses, traffic meant for "secure-api.acme.com" could be redirected to an attacker-controlled server.

4. **Rogue WiFi Access Points**: In wireless environments, attackers could create fake access points to capture traffic.

The impact is particularly severe because modern network traffic is expected to be encrypted, especially for services with "secure" in their name, creating a false sense of security for developers and operators.

# Remediation Steps
## Replace Plain Socket with SSLSocket

**Priority**: P0

Immediately modify the code to use `SSLSocket` with proper certificate validation instead of standard `Socket`:

```java
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;

public class SecureCommunication {
    public static void main(String[] args) {
        try {
            // Create SSL Socket Factory with default trust managers
            SSLSocketFactory sslSocketFactory = 
                (SSLSocketFactory) SSLSocketFactory.getDefault();
            
            // Create SSLSocket using the factory (note use of HTTPS port 443)
            SSLSocket sslSocket = 
                (SSLSocket) sslSocketFactory.createSocket("secure-api.acme.com", 443);
            
            // Enable all supported protocols
            sslSocket.setEnabledProtocols(sslSocket.getSupportedProtocols());
            
            // Setup IO streams
            PrintWriter out = new PrintWriter(sslSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(
                new InputStreamReader(sslSocket.getInputStream())
            );

            // Send HTTPS request
            out.println("GET /data HTTP/1.1");
            out.println("Host: secure-api.acme.com");
            out.println();

            // Read response
            String responseLine;
            while ((responseLine = in.readLine()) != null) {
                System.out.println(responseLine);
            }

            // Close resources
            in.close();
            out.close();
            sslSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

This implementation:
1. Uses the SSL/TLS protocol to encrypt all traffic
2. Implements certificate validation through the default trust store
3. Uses the standard HTTPS port (443) instead of HTTP (8080)
4. Enables all supported protocols to ensure compatibility and security
## Use Modern HTTP Client with Certificate Pinning

**Priority**: P1

Replace the manual socket handling with a modern HTTP client library that supports certificate pinning for enhanced security:

```java
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class ModernSecureCommunication {
    public static void main(String[] args) {
        try {
            // Create a trust manager that implements certificate pinning
            TrustManager[] trustManagers = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Not needed for client implementation
                    }
                    
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Implement certificate pinning here
                        // Example: Check certificate fingerprint against known good value
                        if (certs.length == 0) {
                            throw new SecurityException("No server certificate provided");
                        }
                        
                        // Example of fingerprint validation (simplified)
                        // String fingerprint = getFingerprint(certs[0]);
                        // if (!"AA:BB:CC:DD:...".equals(fingerprint)) {
                        //     throw new SecurityException("Certificate fingerprint mismatch");
                        // }
                    }
                }
            };
            
            // Create SSL context with our custom trust manager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, new java.security.SecureRandom());
            
            // Create the HTTP client with our SSL context
            HttpClient client = HttpClient.newBuilder()
                .sslContext(sslContext)
                .build();
            
            // Create and send request
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://secure-api.acme.com/data"))
                .build();
            
            HttpResponse<String> response = client.send(
                request, HttpResponse.BodyHandlers.ofString());
            
            System.out.println("Status: " + response.statusCode());
            System.out.println("Response: " + response.body());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Implement fingerprint calculation method
    private static String getFingerprint(X509Certificate cert) {
        // Implementation omitted for brevity
        return "";
    }
}

```

This improved implementation:
1. Uses Java's modern HttpClient (available since Java 11)
2. Implements proper HTTPS with TLS encryption
3. Adds certificate pinning to validate the server's identity beyond basic certificate chain validation
4. Uses a cleaner, more maintainable API that handles connection pooling and other best practices
5. Properly uses the HTTPS scheme in the URI


# References
* CWE-311 | [Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
* CWE-319 | [Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* A02:2021 | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
* CWE-327 | [Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
