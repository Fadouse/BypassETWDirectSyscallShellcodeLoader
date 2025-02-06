# BypassETWDirectSyscallShellcodeLoader

**BypassETWDirectSyscallShellcodeLoader** is a Windows-based shellcode loader that bypasses ETW (Event Tracing for Windows) monitoring and leverages direct system calls for process injection. The project integrates multiple anti-debugging, anti-sandbox techniques, and dynamic NT API parsing methods. It is intended as a reference for research and learning in reverse engineering and system security techniques.

> **Important Disclaimer**  
> This project is for educational and research purposes only. It is strictly prohibited to use it for any illegal or malicious activities. Users are solely responsible for any consequences arising from its use, and the author assumes no legal liability.

---

## Project Features

- **ETW Bypass**  
  Modifies the first byte of the `EtwEventWrite` function to a `RET` instruction, effectively bypassing ETW monitoring.

- **Anti-Debugging and Anti-Sandbox Detection**  
  Utilizes techniques such as `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and various memory and processor checks to determine if a debugger or sandbox environment (e.g., Sandboxie) is present.

- **Dynamic API Resolution**  
  Iterates through the export table of `ntdll.dll` and dynamically retrieves critical NT API addresses by comparing Base64-encoded API names and hashes, thereby enhancing code stealth.

- **Process Injection Technique**  
  Employs remote thread injection: allocates memory in the target process, writes XOR-encrypted (using key `0xAA`) shellcode into it, and creates a remote thread to execute the decrypted shellcode.

- **Delayed Execution**  
  Implements a delay strategy that does not rely on the typical Sleep function, increasing the difficulty for both static analysis and dynamic detection.

---

## Project Structure

```plaintext
BypassETWDirectSyscallShellcodeLoader/
├── README.md                   # Project description and documentation
├── main.c                      # Main source code file
```

---

## How to Use

### System Requirements

- **Operating System:** Windows  
- **Development Environment:** Microsoft Visual Studio (with the Windows SDK configured)

### Build Steps

1. **Import the Code**  
   Download the `main.c` file and any related files into your working directory.

2. **Create a Project**  
   In Visual Studio, create a new C/C++ project and add the downloaded source files to the project.

3. **Compile the Project**  
   Use Visual Studio’s default configuration to compile the project. Note that some antivirus engines (VirusTotal reported only 6 detections) might flag the compiled binary as suspicious.

### Running the Program

- Run the compiled executable directly.  
- The program first performs anti-debugging, anti-sandbox detection, and delayed execution to avoid static and dynamic analysis.  
- It then bypasses ETW, elevates privileges (enabling debug privileges), dynamically resolves NT APIs, and decrypts the built-in shellcode (which is XOR encrypted).  
- Finally, it injects the decrypted shellcode into a target process (e.g., `explorer.exe`) via remote thread creation.

---

## Analysis Links

- [VirusTotal Analysis](https://www.virustotal.com/gui/file/3c220b93f4fe03e48e788514be11404b20ef6587391e190ed615fdd11a29e340)
- [Triage Sandbox Analysis](https://tria.ge/250206-lz2xdatkgq)
- [Any.Run Sandbox Task](https://app.any.run/tasks/b072ba65-4c95-40c7-9998-f9fdb8e84f50)

---

## Notes

- **For Educational Purposes Only**  
  All code and techniques in this project are solely for security research and reverse engineering learning purposes. Do not use them for any illegal activities.

- **False Positives**  
  Because the project involves low-level system operations and bypassing security mechanisms, some antivirus engines may flag the compiled binary. It is recommended to conduct research and testing in a secure, controlled environment.

- **Legal Responsibility**  
  Users must comply with the laws and regulations of their jurisdiction. The author is not responsible for any legal issues or security incidents arising from the use of this project.

---

## Contributions and Feedback

Contributions, suggestions, and code enhancements are welcome. Please contact us via [GitHub Issues](https://github.com/Fadouse/BypassETWDirectSyscallShellcodeLoader/issues) or submit a Pull Request.

---

## Contact

For any questions or further discussion, please contact the author at: [fadouse@turings.org](mailto:fadouse@turings.org)

---

> **Disclaimer:** This project and its accompanying documentation are provided solely for research and educational purposes. The author is not responsible for any legal or security issues resulting from its use.

---

**Additional Note:**  
This project was assisted by ChatGPT o3 mini high and Deepseek r1.
