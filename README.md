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

## Steps

Below are screenshots showcasing various parts of the LogDefender system. Each one includes a short explanation to help understand the module's purpose.

---

### *Ref 1: Project Architecture*

![Architecture](https://i.imgur.com/yourimage1.png)  
*This diagram explains the modular structure of LogDefender, detailing how the core detection logic, GUI, database, and dashboard components interact.*

---

### *Ref 2: Real-Time Process Scanner*

![Process Scanner](https://i.imgur.com/yourimage2.png)  
*Shows the process scanning module in action, highlighting suspicious processes based on known keylogger signatures and hash comparisons.*

---

### *Ref 3: Keyboard Hook Detection*

![Hook Detection](https://i.imgur.com/yourimage3.png)  
*Demonstrates the detection of active keyboard hooks, a common trait of keyloggers. Detected hooks are logged with timestamps.*

---

### *Ref 4: GUI - Main Dashboard*

![GUI Dashboard](https://i.imgur.com/yourimage4.png)  
*Displays the CustomTkinter-based graphical user interface with options to scan, view logs, and export results.*

---

### *Ref 5: Streamlit Log Dashboard*

![Streamlit](https://i.imgur.com/yourimage5.png)  
*Live Streamlit interface showing detection logs and threat analytics in real time.*

---

### *Ref 6: Database Logging*

![Database](https://i.imgur.com/yourimage6.png)  
*Sample screenshot of the SQLite database table capturing logs of detected threats, including timestamps, process names, hashes, and detection flags.*

---

### *Ref 7: Terminal View*

![Terminal](https://i.imgur.com/yourimage7.png)  
*CLI view of the LogDefender for users preferring terminal-based interaction.*

---

## Contribution

Feel free to fork the repository, create a branch, and suggest enhancements. Whether it's new detection modules, improved visualizations, or performance optimizations—contributions are welcome.

---

## License

This project is licensed under the [MIT License](LICENSE).
