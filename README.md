# LogDefender

## Objective

The **LogDefender** project was developed as a real-time keylogger detection system with an emphasis on modular design, user accessibility, and effectiveness in threat detection. The goal was to build a Python-based tool capable of identifying keyloggers and suspicious activities by analyzing processes, file hashes, remote connections, and keyboard hooks. LogDefender provides both CLI and GUI interfaces and supports logging, database storage, and Streamlit dashboards for data visualization. This project was developed as part of the final year BCA major project.

### Skills Learned

- Deep understanding of keylogger behavior and detection mechanisms.
- Expertise in real-time process and file monitoring using `psutil` and `hashlib`.
- Database integration using `sqlite3` for persistent threat logging.
- GUI development with `Tkinter` and `CustomTkinter`, along with Streamlit dashboards.
- Modular Python programming and project structuring.
- Network security fundamentals including remote connection analysis.
- Implementation of secure hash validation and anomaly detection logic.

### Tools Used

- **Python** – Core programming language for detection logic and GUI.
- **psutil** – For system process and connection scanning.
- **pynput** – To detect active keyboard hooks.
- **hashlib** – For hashing and comparing process/file binaries.
- **sqlite3** – Embedded database for logging detections.
- **CustomTkinter** – To build a modern and interactive GUI.
- **Streamlit** – For live dashboard visualization of detection logs.
- **PHP** – Used for an optional web frontend to display database logs.
