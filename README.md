# USBGuard Windows Service
### Enforce BitLocker encryption policy on all USB drives — automatically.

---

## What It Does

| USB Drive Status       | Service Running (ON)                        | Service Stopped (OFF) |
|------------------------|---------------------------------------------|-----------------------|
| **BitLocker Protected**| ✅ Allowed silently, no action              | ✅ Normal             |
| **Not Encrypted**      | ⚠️ Warning popup shown → drive ejected     | ✅ Normal             |

Monitoring is **continuous and event-driven** — every USB insertion, forever.

---

## Requirements

- Windows 10 / 11 (64-bit)
- Python 3.8+ installed and on PATH
- Administrator privileges
- BitLocker must be enabled on the system (required for WMI encryption queries)

---

## Installation

### Step 1 — Install Python dependencies

Open **Command Prompt as Administrator** and run:

```
pip install pywin32 wmi
```

After installing pywin32, run the post-install script once:

```
python Scripts/pywin32_postinstall.py -install
```

> If `Scripts` is not found, locate it in your Python directory, e.g.:
> `C:\Python311\Scripts\pywin32_postinstall.py`

---

### Step 2 — Place the service file

Copy `usb_guard_service.py` to a permanent folder.
**Do not move it after installation.** For example:

```
C:\USBGuard\usb_guard_service.py
```

---

### Step 3 — Install the Windows Service

Open **Command Prompt as Administrator**, navigate to the folder and run:

```
cd C:\USBGuard
python usb_guard_service.py install
```

You should see:
```
Installing service USBGuardService
Service installed
```

---

### Step 4 — Start the Service

```
python usb_guard_service.py start
```

Or open **services.msc**, find **USB Guard Service**, right-click → **Start**.

---

## Controlling the Service

### Via Command Line (run as Administrator)

| Action         | Command                                    |
|----------------|--------------------------------------------|
| Start          | `python usb_guard_service.py start`        |
| Stop           | `python usb_guard_service.py stop`         |
| Restart        | `python usb_guard_service.py restart`      |
| Uninstall      | `python usb_guard_service.py remove`       |

### Via Windows GUI

- **services.msc** — Open Services Manager, find "USB Guard Service"
- **Task Manager** → Services tab → Right-click "USBGuardService"

---

## Auto-Start on Boot (Optional)

After installing, set the service to start automatically:

```
sc config USBGuardService start= auto
```

---

## Log File

All events are logged to:

```
C:\ProgramData\USBGuard\usb_guard.log
```

Example log entries:

```
2025-01-15 09:32:11  [INFO    ]  USBGuard Service STARTED
2025-01-15 09:34:05  [INFO    ]  === USB INSERT detected  →  drive E: ===
2025-01-15 09:34:05  [WARNING ]  Drive E: is NOT encrypted by BitLocker – enforcing policy.
2025-01-15 09:34:07  [INFO    ]  Warning popup displayed for E:
2025-01-15 09:34:09  [INFO    ]  Drive E: ejected successfully (IOCTL method)
2025-01-15 09:41:22  [INFO    ]  === USB INSERT detected  →  drive F: ===
2025-01-15 09:41:22  [INFO    ]  Drive F: is BitLocker-PROTECTED – allowed, no action taken.
2025-01-15 09:45:10  [INFO    ]  === USB REMOVE detected  →  drive F: ===
```

The log rotates automatically at 5 MB, keeping one backup copy.

---

## How the Service Handles Each Drive

```
USB Inserted
     │
     ▼
Query BitLocker status (WMI)
     │
     ├── Protected? ──YES──► Log "Allowed" → Do nothing
     │
     └── Not Protected? ─────► Show warning popup (non-blocking)
                                    │
                                    ▼
                               Wait 2 seconds
                                    │
                                    ▼
                          Try IOCTL eject (fast)
                                    │
                                    ├── Success? → Log "Ejected"
                                    │
                                    └── Failed? → Try diskpart eject
                                                       │
                                                       └── Log result
```

---

## Uninstallation

```
python usb_guard_service.py stop
python usb_guard_service.py remove
```

Then delete the folder and the log directory:

```
rmdir /s /q C:\USBGuard
rmdir /s /q C:\ProgramData\USBGuard
```

---

## Troubleshooting

### Service fails to start

- Make sure you ran `pip install pywin32 wmi` as Administrator
- Make sure you ran `pywin32_postinstall.py -install`
- Check the log at `C:\ProgramData\USBGuard\usb_guard.log`
- Check Windows Event Viewer → Windows Logs → Application for errors

### Warning popup does not appear

- The service runs as **SYSTEM** which cannot always show UI on the interactive desktop in newer Windows versions
- If popup does not show: open **services.msc** → right-click USBGuardService → Properties → Log On tab → check **Allow service to interact with desktop**
- The drive is still ejected even if the popup is not visible

### Drive is not being ejected

- Some drives require the user to close all open files before ejection works
- Check the log — if IOCTL fails, the diskpart fallback is tried automatically
- If both methods fail, it is logged as an error

### BitLocker WMI query fails

- The service requires admin privileges — make sure the service is running as **Local System**
- BitLocker must be available on your Windows edition (not available on Windows Home)

---

## Files

```
usb_guard_service.py    ← The service (only file needed)
README.md               ← This file
C:\ProgramData\USBGuard\usb_guard.log   ← Generated at runtime
```
