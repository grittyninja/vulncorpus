# VulnCorpus: A Security Vulnerability Report Dataset

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Dataset Size: 101 Reports](https://img.shields.io/badge/Dataset_Size-101_Reports-green.svg)]()
[![Format: Markdown](https://img.shields.io/badge/Format-Markdown-yellow.svg)]()

## Overview

VulnCorpus is a structured collection of 101 detailed security vulnerability reports designed for cybersecurity research, education, and machine learning applications. Each report follows a standardized format with comprehensive vulnerability analysis, CVSS scoring, exploitation scenarios, and remediation strategies based on real-world security issues across multiple technologies and platforms.

## Description

The security research community has long faced challenges regarding access to high-quality, well-structured vulnerability data suitable for research and model training. VulnCorpus addresses this need by providing a meticulously curated corpus of vulnerability reports that maintain consistent formatting and analytical depth while covering diverse security issues.

The reports in this corpus provide both technical depth and contextual information about how vulnerabilities manifest in real systems. This makes them valuable not only for technical analysis but also for understanding the broader security implications and business impact of different vulnerability types.

## Document Structure

Each vulnerability report in the corpus adheres to a consistent Markdown structure with the following sections:

1. **Vulnerability Case** - Detailed description of the vulnerability context and affected code
2. **Vulnerability Breakdown** - Systematic analysis of vulnerability elements, vectors, and severity
3. **Description** - Concise technical summary
4. **CVSS** - Standardized severity scoring with complete vector notation
5. **Exploitation Scenarios** - Practical examples of how vulnerabilities could be exploited
6. **Impact Analysis** - Business and technical impact assessment
7. **Technical Details** - In-depth technical analysis
8. **Remediation Steps** - Prioritized approaches to vulnerability mitigation
9. **References** - Related CWEs, standards, and resources

## Coverage

The corpus encompasses diverse vulnerability types including but not limited to:

- Injection vulnerabilities (SQL, NoSQL, LDAP, XPath, Command)
- Cross-site scripting (XSS) and Cross-site request forgery (CSRF)
- Authentication and authorization flaws
- Cryptographic implementation issues
- Path traversal and file inclusion
- XML External Entity (XXE) processing
- Insecure deserialization
- Docker and container security issues
- gRPC security flaws
- And many more

Reports cover multiple programming languages and frameworks including Go, Java, C/C++, C#, JavaScript, .NET Core, and various web technologies.

## Usage Examples

### Basic Repository Statistics

```python
import glob
import re
from collections import Counter

# Count occurrences of different vulnerability types
vulnerability_types = []
for file_path in glob.glob("data/*.md"):
    with open(file_path, 'r') as file:
        content = file.read()
        # Extract vulnerability type from title
        match = re.search(r'^# (.+?)(\n|$)', content, re.MULTILINE)
        if match:
            vulnerability_types.append(match.group(1))

type_distribution = Counter(vulnerability_types)
print(type_distribution.most_common(10))
```

### CVSS Score Analysis

```python
import glob
import re
import statistics

# Extract and analyze CVSS scores
scores = []
for file_path in glob.glob("data/*.md"):
    with open(file_path, 'r') as file:
        content = file.read()
        # Extract CVSS score
        match = re.search(r'\*\*Score\*\*: (\d+\.\d+)', content)
        if match:
            scores.append(float(match.group(1)))

print(f"Average CVSS score: {statistics.mean(scores)}")
print(f"Median CVSS score: {statistics.median(scores)}")
print(f"Score range: {min(scores)} - {max(scores)}")
```

## Applications

VulnCorpus is particularly valuable for:

### Research
- Training and evaluating machine learning models for vulnerability detection and classification
- Analyzing patterns in vulnerability discovery, exploitation, and remediation
- Testing natural language processing on security text
- Developing automated vulnerability assessment tools

### Education
- Case studies for cybersecurity courses
- Reference material for security certification preparation
- Realistic examples for penetration testing training
- Materials for capture-the-flag (CTF) challenge creation

### Industry
- Reference for security engineers developing secure code
- Training material for security awareness programs
- Examples for security assessment reporting
- Baseline for developing internal security standards

## Contributing

Contributions to VulnCorpus are welcome. Please consider the following guidelines:

1. All new vulnerability reports must follow the established template structure
2. Reports should be based on realistic vulnerability patterns
3. Code examples should be illustrative but not copied from real vulnerable codebases
4. CVSS scoring should follow CVSS 3.1 standards with proper vector calculation

## Citation

If you use VulnCorpus in your research, please cite it as follows:

```bibtex
@misc{vulncorpus2025,
  author = {Nugraha H},
  title = {VulnCorpus: A Security Vulnerability Report Dataset},
  year = {2025},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://github.com/grittyninja/vulncorpus}}
}
```

## License

This corpus is made available under the MIT License.

## Acknowledgments

- Inspired by related datasets including CVEDetails, the CWE Top 25, and OWASP's vulnerability knowledge base
- Created to support the cybersecurity research and education community
