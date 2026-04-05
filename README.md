# Kaminsky DNS Cache Poisoning Attack Implementation

This repository contains a professional Proof-of-Concept (PoC) implementation of the Kaminsky DNS Cache Poisoning Attack, developed in accordance with SEED Lab standards for academic and research purposes.

## Overview

The Kaminsky attack (also known as the "DNS Delegation Attack") allows an attacker to poison the cache of a recursive DNS resolver by spoofing authoritative responses. This implementation utilizes a high-performance C-based engine for packet flooding and Python/Scapy for binary template generation.

**Project Implementation:**
This repository provides the complete source code implementation for the attack methodology described in the accompanying **[report.pdf](file:///home/emre/Desktop/Codes/School%20Related/Kaminsky-Attack-Implementation/report.pdf)** and **[presentation.pptx](file:///home/emre/Desktop/Codes/School%20Related/Kaminsky-Attack-Implementation/presentation.pptx)**. These codes are not just a reference but a ready-to-use toolset for replicating the results detailed in the project documentation. Since the report contains the step-by-step methodology and theoretical background, this repository serves as the actual implementation that users can directly execute to perform the attack in their own environment.

### Key Components

- **`attack.c`**: High-performance raw socket engine for Transaction ID (TX ID) brute-forcing.
- **`generate_bin.py`**: Python script to generate `ip_req.bin` and `ip_resp.bin` templates using Scapy.
- **`dns_request.py`**: A standalone Scapy script to trigger a single DNS recursive lookup.
- **`dns_reply.py`**: A standalone Scapy script for manual spoofing validation.
- **`requirement.txt`**: Python dependencies (Scapy) for the helper scripts.
- **`report.pdf`**: Comprehensive academic report detailing the attack theory and setup.
- **`presentation.pptx`**: Presentation slides summarizing the attack workflow and results.
