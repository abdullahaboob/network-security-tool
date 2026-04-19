\# Network Security Tool 🔍

\*\*Course:\*\* 605346 - Information \& Network Security Programming  

\*\*Student:\*\* abdullahaboob  

\*\*University:\*\* University of Petra



\---



\## 📌 What is this tool?

A multithreaded command-line port scanner built in Python.  

It scans TCP ports on one or more targets simultaneously using multiple threads.



\---



\## 🚀 How to Use



\### Basic scan:

```bash

python scanner.py -t scanme.nmap.org -p 1-100

```



\### Scan multiple targets:

```bash

python scanner.py -t 192.168.1.1,scanme.nmap.org -p 22,80,443

```



\### Full options:

```bash

python scanner.py -t <target> -p <ports> --threads <number> --timeout <seconds>

```



| Argument | Description | Default |

|----------|-------------|---------|

| `-t` | Target host or IP | Required |

| `-p` | Ports to scan (e.g. 1-1024 or 22,80,443) | 1-1024 |

| `--threads` | Number of concurrent threads | 100 |

| `--timeout` | Socket timeout in seconds | 1.0 |



\---



\## 🧵 Thread Safety Design

\- `ThreadPoolExecutor` manages all threads efficiently

\- `threading.Lock()` ensures only one thread writes to the log file at a time

\- This prevents race conditions and data corruption in the output file



\---



\## 📁 Output

\- Results are printed to the console in real time

\- A timestamped log file is saved automatically (e.g. `scan\_results\_20260419\_122845.txt`)

\- A backup copy is saved in the `logs\_backup/` folder using `shutil`



\---



\## 🔧 Requirements

\- Python 3.x

\- No external libraries needed (uses built-in modules only)

