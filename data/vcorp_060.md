# Zip Bomb Vulnerability in File Upload Microservice

# Vulnerability Case
During a routine security assessment of Acme Corp's Go-based file upload microservice (running on Go 1.17 within Docker containers on Ubuntu nodes in AWS), we discovered that the decompression logic for authenticated user-supplied ZIP files lacked a limit on the decompressed size. The function uses an unbounded call to `io.Copy` when processing ZIP entries, which renders it susceptible to a decompression bomb attack. During our testing, specially crafted ZIP files expanded to an unexpectedly large size upon decompression, leading to significant memory and CPU consumption. This behavior, indicative of a potential denial-of-service (DoS) scenario, was confirmed through automated fuzzing and integration testing.

Below is a simplified Go code snippet representing the vulnerable pattern:

```go
package main

import (
        "archive/zip"
        "bytes"
        "io"
        "log"
)

func processZip(filePath string) error {
        // Open the ZIP file for processing
        r, err := zip.OpenReader(filePath)
        if err != nil {
                return err
        }
        defer r.Close()

        for _, zf := range r.File {
                rc, err := zf.Open()
                if err != nil {
                        return err
                }
                // Vulnerable pattern: decompressed data is read without imposing a limit
                var outBuffer bytes.Buffer
                if _, err = io.Copy(&outBuffer, rc); err != nil {
                        rc.Close()
                        return err
                }
                rc.Close()
                log.Printf("Processed file: %s, size: %d bytes", zf.Name, outBuffer.Len())
        }
        return nil
}

func main() {
        if err := processZip("example.zip"); err != nil {
                log.Fatal(err)
        }
}
```

The vulnerability arises from the absence of a cap on the amount of data read during decompression. In a typical deployment, an authenticated attacker can supply a ZIP archive (commonly known as a ZIP bomb) where the compressed size is modest but inflates to gigabytes upon decompression. By exploiting this, an adversary could trigger extreme memory and CPU exhaustion, leading to a denial-of-service condition. In a production environment, this may result in prolonged service downtime and degraded performance, ultimately causing significant business disruption and potentially impacting critical operational workflows.

context: go.lang.security.decompression_bomb.potential-dos-via-decompression-bomb Detected a possible denial-of-service via a zip bomb attack. By limiting the max bytes read, you can mitigate this attack. `io.CopyN()` can specify a size.

# Vulnerability Breakdown
This vulnerability involves an unbounded decompression mechanism in Acme Corp's Go-based file upload microservice that allows attackers to perform denial-of-service attacks through specially crafted ZIP files.

1. **Key vulnerability elements**:
   - Unbounded use of `io.Copy()` when extracting ZIP archives
   - No limits on decompressed file size
   - No validation of compression ratios
   - Running in containerized environment with shared resources
   - Directly processes user-supplied content
   - Access restricted to authenticated users

2. **Potential attack vectors**:
   - Classic ZIP bombs (tiny compressed files that expand to gigabytes)
   - Recursive/nested ZIP archives
   - Coordinated upload of multiple ZIP bombs
   - Timed attacks during peak business operations

3. **Severity assessment**:
   - Primary impact is on availability through resource exhaustion
   - No direct impact on confidentiality or integrity
   - Attack vector is network-based as it involves uploading files
   - Low complexity to exploit (ZIP bombs are well-known and easy to create)
   - Low privileges required (authentication needed)

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): None (N) 
   - Integrity (I): None (N) 
   - Availability (A): High (H) 

# Description
A medium-severity vulnerability has been identified in Acme Corp's Go-based file upload microservice. The service improperly handles decompression of ZIP files by using an unbounded `io.Copy()` function without implementing size limits, making it susceptible to decompression bomb attacks.

The vulnerable code reads and processes the contents of uploaded ZIP files without validating or limiting the decompressed size. This allows malicious users to upload specially crafted ZIP files (ZIP bombs) that contain highly compressed data which expands to an extremely large size during decompression, consuming excessive memory and CPU resources.

During security testing, this vulnerability was confirmed by uploading crafted ZIP files that caused significant resource consumption, potentially leading to denial-of-service conditions. The service runs in Docker containers on Ubuntu nodes in AWS, meaning that resource exhaustion could affect not only the microservice itself but potentially impact other services sharing the same infrastructure.

Importantly, the application requires user authentication before file uploads can be performed, which reduces the potential attack surface and limits exploitation to authenticated users only.

# CVSS
**Score**: 6.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H \
**Severity**: Medium

The Medium severity rating (6.5) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely by any user who can upload files to the microservice, allowing for wide accessibility.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability requires minimal technical knowledge. Creating ZIP bombs is well-documented and relatively straightforward.

- **Low Privileges Required (PR:L)**: The application requires authentication before uploads can be performed, limiting the attack to authenticated users only. This significantly reduces the potential attack surface compared to a public-facing service.

- **No User Interaction (UI:N)**: The attack can be executed directly against the service without requiring any actions from users or administrators.

- **Unchanged Scope (S:U)**: The impact is contained to the vulnerable microservice itself, not directly affecting other components.

- **No Confidentiality Impact (C:N)**: The vulnerability does not expose sensitive information.

- **No Integrity Impact (I:N)**: The vulnerability does not allow modification of data.

- **High Availability Impact (A:H)**: Successful exploitation can cause complete denial of service by exhausting system resources, making the service unavailable for legitimate use. In containerized environments like AWS, this could potentially affect other services sharing resources.

The authentication requirement reduces the severity from High to Medium, as it limits potential attackers to those who already have valid credentials for the system.

# Exploitation Scenarios
**Scenario 1: Basic ZIP Bomb Attack**
An authenticated user creates a small ZIP file (e.g., 1MB) that contains highly compressed repetitive data designed to expand to several gigabytes when decompressed. When uploaded to the file service, the decompression process consumes excessive memory as it attempts to process the expanding data without limits. This causes the container to exhaust its memory allocation, triggering either container crashes or severe performance degradation.

**Scenario 2: Nested ZIP Bombs**
An authenticated attacker uploads a ZIP file containing multiple nested ZIP files, each of which is itself a ZIP bomb. As the service processes each layer, it decompresses exponentially larger amounts of data. For example, a 10KB file might contain 10 nested archives, each expanding to 1GB, resulting in the processing of up to 10GB of data. This recursive decompression amplifies the resource consumption beyond what would be possible with a single-layer ZIP bomb.

**Scenario 3: Coordinated DoS Campaign**
Multiple authenticated users (or a single attacker using multiple accounts) coordinate to upload numerous ZIP bombs simultaneously. This distributed approach overwhelms the service and underlying infrastructure more quickly than a single upload could, potentially affecting other services in the same AWS environment due to shared resource contention. The attack might be timed to coincide with peak business hours to maximize impact.

**Scenario 4: Insider Threat**
A disgruntled employee with valid authentication credentials deliberately launches a ZIP bomb attack during a critical business period to disrupt operations. The employee might use knowledge of system peak times and resource constraints to maximize the impact of the attack while minimizing the chance of immediate detection.

# Impact Analysis
**Business Impact:**
- Service unavailability during attacks, potentially affecting customer operations and satisfaction
- Unplanned downtime leading to violations of Service Level Agreements (SLAs) and potential financial penalties
- Revenue loss during outage periods for business-critical operations dependent on file processing
- Increased operational costs due to automatic scaling in AWS responding to high resource utilization
- IT operations team distraction for incident response and remediation
- Potential reputation damage if service disruptions become frequent or prolonged

**Technical Impact:**
- Complete service unavailability during active exploitation
- Memory exhaustion in container environments leading to OOM (Out of Memory) kills by the container runtime
- Excessive CPU consumption affecting performance of co-located services
- Potential cascading failures to dependent microservices
- Increased load on AWS infrastructure potentially triggering auto-scaling and associated costs
- Reduced capacity to handle legitimate requests during attacks
- System instability and unpredictable behavior under resource pressure
- Potential data corruption if processes are terminated abruptly during file processing

While the authentication requirement limits the potential attackers to those with valid credentials, the technical impact of a successful exploitation remains significant, particularly if multiple authenticated users coordinate an attack or if an insider threat exploits the vulnerability.

# Technical Details
The vulnerability stems from the use of unbounded `io.Copy()` when decompressing ZIP file entries, without implementing proper size limits or validation checks. Here's the vulnerable code pattern:

```go
func processZip(filePath string) error {
	// Open the ZIP file for processing
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, zf := range r.File {
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		// Vulnerable pattern: decompressed data is read without imposing a limit
		var outBuffer bytes.Buffer
		if _, err = io.Copy(&outBuffer, rc); err != nil {
			rc.Close()
			return err
		}
		rc.Close()
		log.Printf("Processed file: %s, size: %d bytes", zf.Name, outBuffer.Len())
	}
	return nil
}

```

**Vulnerability Mechanism:**

1. The function reads ZIP entries and decompresses them into memory using an unbounded buffer
2. It uses `io.Copy()` which will continue copying data until EOF or an error occurs
3. No checks are implemented to:
   - Limit the maximum decompressed size
   - Validate the compression ratio
   - Restrict the total memory usage
   - Implement timeouts for the decompression process

**Authentication Context:**
While the application requires authentication before uploads can be performed, this only limits who can exploit the vulnerability but does not prevent the vulnerability itself. Once authenticated, users can still upload ZIP bombs that will be processed without proper size limits.

**ZIP Bomb Technical Details:**

ZIP bombs typically exploit the high compression ratios possible with repetitive data. For example:

- A 1MB ZIP file might contain a single file with highly repetitive content that expands to 10GB+ when decompressed
- In extreme cases, sophisticated ZIP bombs can achieve compression ratios exceeding 1:1,000,000
- The "42.zip" example is a well-known ZIP bomb that is only 42KB compressed but contains nested ZIP files that would decompress to 4.5 petabytes

**Exploitation Factors:**

1. **Container Environment Impact:** In Docker containers, memory is typically limited by cgroup constraints. When the process exceeds these limits, the container engine will terminate the process with an OOM (Out of Memory) kill.

2. **AWS Infrastructure Considerations:** In an AWS environment, excessive resource usage may trigger auto-scaling, potentially increasing costs during an attack. It may also affect other services sharing the same underlying infrastructure.

3. **Go's Memory Management:** Go's garbage collector may struggle under these conditions, as large objects are created rapidly during decompression, potentially leading to increased GC pressure and further performance degradation.

# Remediation Steps
## Implement Size-Limited Decompression

**Priority**: P0

Replace the unlimited `io.Copy()` with `io.CopyN()` to enforce a maximum decompression size per file:

```go
func processZip(filePath string) error {
	// Open the ZIP file for processing
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return err
	}
	defer r.Close()

	// Set a reasonable maximum decompressed size per file (e.g., 100MB)
	const maxDecompressedSize int64 = 100 * 1024 * 1024 // 100MB
	// Track total decompressed size across all files
	var totalDecompressed int64 = 0
	// Set a reasonable maximum for the total decompressed size of all files combined
	const maxTotalDecompressedSize int64 = 1 * 1024 * 1024 * 1024 // 1GB

	for _, zf := range r.File {
		// Check if the claimed uncompressed size exceeds our limit
		if zf.UncompressedSize64 > uint64(maxDecompressedSize) {
			return fmt.Errorf("file %s too large: %d bytes exceeds limit of %d", 
				zf.Name, zf.UncompressedSize64, maxDecompressedSize)
		}

		// Check if adding this file would exceed our total size limit
		if totalDecompressed + int64(zf.UncompressedSize64) > maxTotalDecompressedSize {
			return fmt.Errorf("total decompressed size would exceed limit of %d bytes", 
				maxTotalDecompressedSize)
		}

		rc, err := zf.Open()
		if err != nil {
			return err
		}

		// Use LimitReader to cap the amount of data read
		limitedReader := io.LimitReader(rc, maxDecompressedSize)
		var outBuffer bytes.Buffer
		n, err := io.Copy(&outBuffer, limitedReader)
		rc.Close()

		if err != nil {
			return err
		}

		// Verify the size matches what was claimed in the header
		if n != int64(zf.UncompressedSize64) {
			return fmt.Errorf("decompressed size %d doesn't match header claim %d for file %s", 
				n, zf.UncompressedSize64, zf.Name)
		}

		totalDecompressed += n
		log.Printf("Processed file: %s, size: %d bytes", zf.Name, outBuffer.Len())
	}
	return nil
}

```

This implementation:
1. Sets a maximum size for individual decompressed files
2. Sets a maximum total size for all decompressed files combined
3. Uses `io.LimitReader` to restrict how much data will be read
4. Verifies that the actual decompressed size matches what was claimed in the ZIP header
5. Tracks the total decompressed size across all files
## Implement Compression Ratio Validation

**Priority**: P1

Add validation for suspicious compression ratios to detect potential ZIP bombs before decompression:

```go
func processZip(filePath string) error {
	// Maximum allowed compression ratio (uncompressed:compressed)
	const maxCompressionRatio = 100 // 100:1 ratio limit

	// Get the file size of the compressed ZIP
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	compressedSize := fileInfo.Size()

	// Open the ZIP file for processing
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return err
	}
	defer r.Close()

	// Calculate total claimed uncompressed size
	var totalClaimedSize uint64 = 0
	for _, zf := range r.File {
		totalClaimedSize += zf.UncompressedSize64
	}

	// Check compression ratio
	if compressedSize > 0 && float64(totalClaimedSize)/float64(compressedSize) > maxCompressionRatio {
		return fmt.Errorf("suspicious compression ratio: %f exceeds maximum of %d:1", 
			float64(totalClaimedSize)/float64(compressedSize), maxCompressionRatio)
	}

	// Continue with size-limited decompression as in the previous solution
	// ...

	return nil
}

```

This enhancement:
1. Calculates the overall compression ratio of the ZIP file
2. Rejects files with suspiciously high compression ratios which are typical of ZIP bombs
3. Runs this check before beginning actual decompression, saving resources
4. Can be tuned based on legitimate use cases for your application

Consider implementing additional safeguards:
1. Add timeouts for the decompression process
2. Process files in a separate goroutine with resource monitoring
3. Implement context cancellation for long-running operations


# References
* CWE-400 | [Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* CWE-409 | [Improper Handling of Highly Compressed Data (Data Amplification)](https://cwe.mitre.org/data/definitions/409.html)
