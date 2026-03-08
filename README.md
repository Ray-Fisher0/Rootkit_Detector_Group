
# Rootkit Detector Group Project

A Linux kernel module for detecting rootkit activity by monitoring suspicious access to the system call table. This project is designed for educational and research purposes, providing a robust foundation for kernel security analysis.

---

## Table of Contents
- [What is a Rootkit?](#what-is-a-rootkit)
- [Why Rootkit Detection Matters](#why-rootkit-detection-matters)
- [Overview of How the Rootkit Detector Works](#overview-of-how-the-rootkit-detector-works)
- [How to Run the Detector](#how-to-run-the-detector)
- [Project Structure](#project-structure)
- [License](#license)
- [Contributing](#contributing)
- [Contact](#contact)

---

## What is a Rootkit?

A rootkit is a type of malicious software designed to gain unauthorized access to a computer system, often by hiding its presence and activities from users and security tools. Rootkits typically operate at the kernel level, allowing attackers to intercept system calls, modify kernel data structures, and conceal files or processes. This makes them extremely difficult to detect and remove.

Rootkits are dangerous because they can provide persistent, stealthy control over a system, enabling attackers to steal sensitive information, disable security mechanisms, and install additional malware. Detecting rootkits is crucial for maintaining the integrity and security of operating systems, especially in environments where sensitive data or critical infrastructure is involved.

## Why Rootkit Detection Matters

Rootkit detection is important because rootkits can compromise the trustworthiness of a system, evade traditional antivirus tools, and facilitate further attacks. By monitoring for suspicious kernel activity—such as attempts to access the system call table—our detection module helps identify potential rootkit behavior early, allowing administrators to respond before significant damage occurs.

## Overview of How the Rootkit Detector Works

`module.c` implements the rootkit detection logic using Linux kprobes and kretprobes. Its main features include:

- Registration of a kretprobe on the `kallsyms_lookup_name` function, which is commonly used by rootkits to locate the system call table.
- Architecture-aware helpers to extract the instruction pointer and function arguments from the CPU register set, supporting x86, x86_64, and ARM64.
- Safe copying of kernel strings to avoid faults or buffer overflows.
- Handlers for kretprobe entry and return events, which log suspicious symbol lookups and record relevant process information.
- Creation of a `/proc/kallsyms_alert` entry to expose the latest alert message to user space.
- Proper initialization and cleanup routines for module loading and unloading, including probe registration and `/proc` entry management.

The module is designed to detect and log attempts to access sensitive kernel symbols, providing visibility into potential rootkit activity. All alerts are written to the kernel log and made available via the `/proc` filesystem for monitoring.

---

## How to Run the Detector

Follow these steps to build and run the kernel module:

1. **Build the module:**
   - Ensure you have the necessary kernel headers installed for your system.
   - Run `make` in the project directory to compile the module.

2. **Load the module:**
   - Use `sudo insmod module.ko` to insert the module into the kernel.
   - Check the kernel log (`dmesg`) for messages indicating successful registration with `sudo dmesg | tail`

3. **Monitor alerts:**
   - Read the latest alert message from `/proc/kallsyms_alert` using `cat /proc/kallsyms_alert`.
   - Alerts will also appear in the kernel log.

4. **Unload the module:**
   - Use `sudo rmmod module` to remove the module from the kernel.
   - Check `dmesg` for cleanup messages.

**Note:** Running kernel modules requires root privileges and can affect system stability. Only test on systems where you can safely experiment.

---

## Project Structure

- `module.c` — Main kernel module implementation for rootkit detection.
- `module.h` — Header file containing core definitions and function prototypes.
- `Makefile` — Build instructions for compiling the kernel module.
- `README.md` — Project documentation and instructions.
- `test_module/` — Directory for test modules.

## License

This project is licensed under the GPL-2.0.

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request for review.

## Contact

For questions or collaboration, please contact the project maintainers via GitHub or email.
