# Windows Thread Injection & Mini EDR (User-Mode Detection Engine)

##  Project Overview

This project demonstrates both **offensive and defensive techniques** in Windows security:

* 🔴 **Process Injection Engine** — executes arbitrary code inside a remote process
* 🔵 **Mini EDR (Endpoint Detection Engine)** — detects suspicious thread execution based on memory analysis

The goal is to understand how modern attacks work and how behavioral detection can identify them.

---

##  Architecture

The project consists of two main components:

### 🔴 1. Injection Engine (`inject.cpp`)

Implements a classic **remote thread injection technique**.

### 🔵 2. Detection Engine (`EDR.cpp`)

Implements a **user-mode behavioral scanner** that analyzes threads and memory to detect anomalies.

---

# 🔴 Injection Workflow (Offensive)

The injector follows a well-known attack pattern:

### Step 1: Target Process Discovery

* Enumerates running processes
* Matches process name (e.g., `Binance.exe`)
* Retrieves PID

---

### Step 2: Open Target Process

```cpp
OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | ...)
```

Allows:

* Memory allocation
* Writing data
* Thread creation

---

### Step 3: Allocate Memory in Target

```cpp
VirtualAllocEx(..., MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
```

 Creates **private memory (MEM_PRIVATE)** inside the target process.

---

### Step 4: Write Payload (Shellcode)

```cpp
WriteProcessMemory(...)
```

 Writes raw machine instructions into allocated memory.

---

### Step 5: Change Memory Permissions

```cpp
VirtualProtectEx(..., PAGE_EXECUTE_READ)
```

 Converts memory into executable region.

---

### Step 6: Execute via Remote Thread

```cpp
CreateRemoteThread(..., addr, ...)
```

 A new thread is created with:

```text
Start Address = addr (injected memory)
```

---

##  Internal Execution Detail (Important)

Although the thread is created with `addr`, internally Windows starts execution through:

```text
ntdll!RtlUserThreadStart → addr
```

* Debuggers often show execution inside `ntdll`
* But the **true start address (Win32 start)** is the injected memory

---

# 🔵 Detection Engine (Mini EDR)

The detection engine scans the system and identifies suspicious execution patterns.

---

##  Detection Workflow

### Step 1: Process Enumeration

* Uses `CreateToolhelp32Snapshot`
* Iterates over all active processes

---

### Step 2: Thread Enumeration

* Enumerates all threads per process
* Uses:

```cpp
NtQueryInformationThread(ThreadQuerySetWin32StartAddress)
```

 Retrieves the **actual thread start address**

---

### Step 3: Memory Inspection

* Uses:

```cpp
VirtualQueryEx
```

* Extracts:

  * Memory type (MEM_PRIVATE / MEM_IMAGE)
  * Protection flags (EXECUTE, READ, etc.)
  * Region boundaries

---

### Step 4: Module Mapping

* Enumerates loaded modules (DLLs, EXEs)
* Builds memory ranges:

```text
[ module_base → module_end ]
```

---

### Step 5: Behavioral Detection Logic

A thread is flagged as suspicious if:

```text
Thread start address is:
  → Executable
  → Inside committed memory
  → NOT part of any loaded module
```

---

## Detection Rule

```text
EXECUTABLE MEMORY
THREAD INVOKED
+ NOT IN MODULE
= HIGHLY SUSPICIOUS
```

---

##  Why This Works

### 🟢 Legitimate Execution

* Threads start inside:

  * Executable (EXE)
  * Loaded DLLs
* Memory type:

```text
MEM_IMAGE
```

---

### 🔴 Malicious Execution (Injection)

* Code is written manually into memory
* Memory type:

```text
MEM_PRIVATE
```

* No module backing
* Thread starts in raw memory

---

## 🔍 Example Detection Output

```text
[!!!] PID 4321 Thread 5678 executing OUTSIDE module
```

Indicates:

* Shellcode execution
* Remote thread injection
* Manual mapping

---

## ⚠️ Debugging Insight

Debugger may show:

```text
win32u.dll / ntdll.dll
```

But:

* This is a wrapper (thread bootstrap)
* Real execution target is retrieved via:

```text
NtQueryInformationThread
```

---

## 🔐 Strengths of This Approach

* Detects:

  * Shellcode injection
  * Reflective DLL loading
  * Manual mapping
* Low false positives
* Based on **behavior**, not signatures

---

##  Limitations

* User-mode only (no kernel visibility)
* Cannot detect all advanced evasion techniques
* LoadLibrary-based injection may bypass detection
* JIT runtimes may appear suspicious

---

##  Future Enhancements

* RWX memory detection
* API hook detection
* Stack inspection
* Thread hijacking detection
* Behavior scoring system
* Real-time monitoring

---

##  How to Run

### Compile

```bash
g++ inject.cpp -o inject.exe
g++ EDR.cpp -o edr.exe
```

### Execute

1. Launch target process
2. Run injector
3. Run EDR scanner

---

##  Key Learning Outcomes

* Windows memory management
* Process & thread internals
* Remote thread injection mechanics
* Difference between:

  * MEM_PRIVATE vs MEM_IMAGE
* Behavioral detection techniques used in EDR systems

---

## ⚠️ Disclaimer

This project is strictly for:

* Educational purposes
* Security research
* Ethical experimentation

Unauthorized use is prohibited.

---

## 👨‍💻 Author

Developed as part of deep exploration into:

* Windows Internals
* Malware Techniques
* Endpoint Detection & Response (EDR)

-----------
## R00K

