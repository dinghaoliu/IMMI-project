# Detecting kernel memory bugs through inconsistent memory management intention inferences

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![USENIX Security 2024](https://img.shields.io/badge/USENIX%20Security-2024-blue.svg)](https://www.usenix.org/system/files/usenixsecurity24-liu-dinghao-detecting.pdf)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Bug Types Detected](#bug-types-detected)
- [Output and Reports](#output-and-reports)
- [Research Paper](#research-paper)
- [Contributing](#contributing)
- [License](#license)
- [Citation](#citation)

## Overview

IMMI is a static analysis tool built on LLVM that detects memory bugs in C/C++ programs.
The tool addresses a critical gap in memory safety analysis by detecting memory bugs that arise from inconsistent memory management intentions, which are common sources of memory leaks and memory corruptions.

## Features

- **Intra-procedural Analysis**: Detects inconsistent memory management within single functions
- **Inter-procedural Analysis**: Identifies bugs across function call boundaries
- **Detailed Bug Reports**: Generates structured reports with source locations and call chains
- **LLVM-Based**: Built on LLVM infrastructure

## Installation

### Prerequisites

- LLVM 15.0
- CMake 3.5.1 or later
- C++17 compatible compiler
- MySQL development libraries (for database features)
- spdlog (for logging functionality)
- nlohmann-json (for JSON processing)

### Building from Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/dinghaoliu/IMMI-project.git
   cd IMMI-project
   ```

2. **Build the analyzer:**
   ```bash
   cd analyzer
   make
   cd ..
   ```

## Usage

### Basic Analysis

```bash
# To analyze a single bitcode file, say "test.bc", run:
./analyzer/build/lib/analyzer test.bc
# To analyze a list of bitcode files, put the absolute paths of the bitcode files in a file, say "bc.list", then run:
./analyzer/build/lib/analyzer @bc.list
```

### Generating Bitcode Files

For optimal analysis precision, O2-optimized bitcode files with debug info remained (-g) are recommended. O2-optimized bitcode files enable more precise error handling path analysis, leading to better bug detection accuracy.

### Configuration

Modify `analyzer/src/configs/configs.toml` to customize:
- Database settings
- Memory allocation and release APIs
- Other settings

## Bug Types Detected

IMMI detects four main categories of memory management bugs:

### 1. Intro-Inconsistency
**Description**: Memory is freed in some error handling paths but not in others within the same function.

### 2. Inter-Inconsistency (Host Free)
**Description**: Callee doesn't free allocated memory, but caller frees the parent structure instead of the specific resource, which leads to memleaks.

### 3. Inter-Inconsistency (Missing Free)
**Description**: Neither callee nor caller properly frees the allocated memory in error paths, which leads to memleaks.

### 4. Inter-Inconsistency (Redundant Free)
**Description**: Both callee and caller attempt to free the same memory, leading to UAF or double-free vulnerabilities.

## Output and Reports

### Bug Reports

After running the analysis, detailed bug reports can be found at:
- **Location**: `analyzer/logs/Bug_Report.txt`
- **Format**: Human-readable text with structured information

Sample bug report format:

```
========================================
BUG REPORT - Intro-inconsistency
========================================
Timestamp: Mon Jan 15 14:30:45 2024
Bug Type: Intro-Inconsistency
Function: vulnerable_function
Description: Heap memory allocated by instruction is freed in some error handling paths but not in others

Allocation Instruction:
  Location: 123: %call = call i8* @malloc(i64 100)
  Instruction: %call = call i8* @malloc(i64 100)

Error Handling Paths That FREE the Memory:
  Path starting at: if.then
    Full path: if.then -> cleanup -> END

Error Handling Paths That DO NOT FREE the Memory:
  Path starting at: if.else
    Full path: if.else -> return -> END

Impact: This inconsistency can lead to memory leaks or UAF/double-free vulnerabilities
Recommendation: Ensure consistent memory management across all error handling paths
========================================
```

## Research Paper

This tool implements the research presented in:

**"Detecting Kernel Memory Bugs through Inconsistent Memory Management Intention Inferences"**  
*USENIX Security Symposium 2024*

**Paper**: [Available at USENIX](https://www.usenix.org/system/files/usenixsecurity24-liu-dinghao-detecting.pdf)

If you use IMMI in your research, please cite our paper:

```bibtex
@inproceedings{liu2024detecting,
  title={Detecting kernel memory bugs through inconsistent memory management intention inferences},
  author={Liu, Dinghao and Lu, Zhipeng and Ji, Shouling and Lu, Kangjie and Chen, Jianhai and Liu, Zhenguang and Liu, Dexin and Cai, Renyi and He, Qinming},
  booktitle={33rd USENIX Security Symposium (USENIX Security 24)},
  pages={4069--4086},
  year={2024}
}
```


## Acknowledgments

- **Zhipeng Lu** ([@AlexiousLu](https://github.com/AlexiousLu)) - Second author of this paper, for his significant contributions in improving the code quality of this project
- LLVM Community for the robust analysis infrastructure
- USENIX Security reviewers for valuable feedback
- All contributors and users who reported issues and suggestions

---

## Contact

For questions, suggestions, or collaborations:

- 📧 **Email**: dinghao.liu@zju.edu.cn, dinghao.liu@sdu.edu.cn
- 🐛 **Issues**: [GitHub Issues](https://github.com/dinghaoliu/IMMI-project/issues)

---

**Keywords**: Memory Safety, Static Analysis, LLVM, Memory Management, Bug Detection, C/C++, Use-After-Free, Memory Leaks, Double-Free
