"""
USBGuard Windows Service
========================
Monitors USB insertions and enforces BitLocker encryption policy.
- Unencrypted USB  →  Warning popup + forced eject
- BitLocker USB    →  Allowed silently
- Service stopped  →  No action taken on any USB

Dependencies:
    pip install pywin32 wmi

Install service:
    python usb_guard_service.py install
    python usb_guard_service.py start

Remove service:
    python usb_guard_service.py stop
    python usb_guard_service.py remove
"""

import sys
import os
import time
import threading
import logging
import subprocess
import ctypes
import ctypes.wintypes
from pathlib import Path
from datetime import datetime

import win32service
import win32serviceutil
import win32event
import servicemanager
import pythoncom
import wmi


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVICE_NAME    = "USBGuardService"
SERVICE_DISPLAY = "USB Guard Service"
SERVICE_DESC    = (
    "Monitors USB insertions and enforces BitLocker encryption policy. "
    "Unencrypted drives are warned and ejected automatically."
)

LOG_DIR      = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "USBGuard"
LOG_FILE     = LOG_DIR / "usb_guard.log"
HISTORY_FILE = LOG_DIR / "usb_history.log"

# How often (seconds) the WMI query loop re-registers if it dies unexpectedly
WMI_RESTART_DELAY = 5

# BitLocker: delay between retries when status is "Unknown" (code 2 = still unlocking)
BITLOCKER_RETRY_DELAY = 3   # seconds between retries, loops forever until clear

# MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL | MB_SETFOREGROUND
_MB_FLAGS = 0x00000000 | 0x00000030 | 0x00001000 | 0x00010000
_MB_TITLE = "USB Guard – Security Warning"


# ---------------------------------------------------------------------------
# Logging setup  (called once when the service starts)
# ---------------------------------------------------------------------------

def _setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    from logging.handlers import RotatingFileHandler

    # ── Main service log (debug + operational messages) ──────────────────────
    logger = logging.getLogger("USBGuard")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=1, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # ── USB History log (one clean line per USB event) ────────────────────────
    history = logging.getLogger("USBGuard.History")
    history.setLevel(logging.INFO)
    history.propagate = False          # don't also write to the main log
    hfmt = logging.Formatter(fmt="%(message)s")   # raw lines only
    hfh = RotatingFileHandler(
        HISTORY_FILE, maxBytes=10 * 1024 * 1024, backupCount=2, encoding="utf-8"
    )
    hfh.setFormatter(hfmt)
    history.addHandler(hfh)

    # Write a header the very first time the file is created / empty
    if HISTORY_FILE.stat().st_size == 0 if HISTORY_FILE.exists() else True:
        header = (
            f"{'TIMESTAMP':<22} {'EVENT':<8} {'DRIVE':<6} {'LABEL':<20} "
            f"{'FS':<8} {'TYPE':<12} {'SIZE_GB':>8} {'BITLOCKER':<14} {'ACTION':<12} SERIAL"
        )
        separator = "-" * len(header)
        history.info(header)
        history.info(separator)

    return logger, history


log, history_log = _setup_logging()


# ---------------------------------------------------------------------------
# Drive info collection  (for history log)
# ---------------------------------------------------------------------------

_DRIVE_TYPE_MAP = {
    0: "Unknown",
    1: "No Root Dir",
    2: "Removable",
    3: "Local Disk",
    4: "Network",
    5: "Compact Disc",
    6: "RAM Disk",
}

def _get_drive_info(drive_letter: str) -> dict:
    """
    Query WMI for detailed info about *drive_letter*.
    Returns a dict with label, filesystem, drive type name, size in GB,
    free space in GB, and volume serial number.
    Falls back gracefully if any field is unavailable.
    """
    info = {
        "label":      "N/A",
        "filesystem": "N/A",
        "type_name":  "N/A",
        "size_gb":    "N/A",
        "free_gb":    "N/A",
        "serial":     "N/A",
    }
    try:
        c = wmi.WMI()
        results = c.Win32_LogicalDisk(DeviceID=drive_letter)
        if not results:
            return info
        d = results[0]

        label = getattr(d, "VolumeName", None)
        info["label"] = (label.strip() if label and label.strip() else "(no label)")

        fs = getattr(d, "FileSystem", None)
        info["filesystem"] = fs if fs else "N/A"

        dtype = getattr(d, "DriveType", None)
        info["type_name"] = _DRIVE_TYPE_MAP.get(dtype, f"Type{dtype}")

        size = getattr(d, "Size", None)
        free = getattr(d, "FreeSpace", None)
        if size and str(size).isdigit():
            info["size_gb"] = f"{int(size) / 1_073_741_824:.2f}"
        if free and str(free).isdigit():
            info["free_gb"] = f"{int(free) / 1_073_741_824:.2f}"

        serial = getattr(d, "VolumeSerialNumber", None)
        info["serial"] = serial if serial else "N/A"

    except Exception as exc:
        log.debug("Could not get drive info for %s: %s", drive_letter, exc)

    return info


def _write_history(event: str, drive_letter: str, bitlocker: str, action: str) -> None:
    """
    Write one structured line to usb_history.log.

    event      : "INSERT" or "REMOVE"
    drive_letter: e.g. "F:"
    bitlocker  : "Protected" / "Unprotected" / "Unknown" / "N/A"
    action     : "Allowed" / "Ejected" / "EjectFailed" / "Removed" / "N/A"
    """
    try:
        info = _get_drive_info(drive_letter)
        ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        line = (
            f"{ts:<22} {event:<8} {drive_letter:<6} "
            f"{info['label']:<20} "
            f"{info['filesystem']:<8} "
            f"{info['type_name']:<12} "
            f"{info['size_gb']:>8} "
            f"{bitlocker:<14} "
            f"{action:<12} "
            f"{info['serial']}"
        )
        history_log.info(line)
        log.debug("History entry written: %s", line.strip())
    except Exception as exc:
        log.error("Failed to write history entry for %s: %s", drive_letter, exc)


# ---------------------------------------------------------------------------
# BitLocker detection
# ---------------------------------------------------------------------------

def _get_bitlocker_status(drive_letter: str) -> str:
    """
    Return BitLocker protection status for *drive_letter*.

    Loops forever on Unknown (code 2) — waits until BitLocker finishes
    unlocking and returns either Protected or Unprotected.
    Never treats Unknown as Unprotected.

        "Unprotected"  → eject
        "Protected"    → allow
        "Unknown"      → keep waiting (retry every BITLOCKER_RETRY_DELAY seconds)
        "WMI_ERROR"    → could not query, treat as Unprotected
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            c = wmi.WMI(namespace=r"root\CIMV2\Security\MicrosoftVolumeEncryption")
            results = c.Win32_EncryptableVolume(DriveLetter=drive_letter)
            if not results:
                log.warning("BitLocker: no WMI result for %s (attempt %d)", drive_letter, attempt)
                return "Unprotected"

            status_code = results[0].ProtectionStatus
            mapping = {0: "Unprotected", 1: "Protected", 2: "Unknown"}
            status = mapping.get(status_code, f"UnknownCode({status_code})")
            log.debug("BitLocker status for %s → %s (code %s, attempt %d)",
                      drive_letter, status, status_code, attempt)

            if status == "Unknown":
                # BitLocker still unlocking — wait and retry forever
                log.info(
                    "BitLocker status Unknown for %s – still unlocking, "
                    "retrying in %ds (attempt %d) …",
                    drive_letter, BITLOCKER_RETRY_DELAY, attempt,
                )
                time.sleep(BITLOCKER_RETRY_DELAY)
                continue

            # Protected or Unprotected — clear result, return immediately
            return status

        except Exception as exc:
            log.error("BitLocker WMI query failed for %s (attempt %d): %s",
                      drive_letter, attempt, exc)
            return "WMI_ERROR"


def _is_bitlocker_protected(drive_letter: str) -> bool:
    status = _get_bitlocker_status(drive_letter)
    return status == "Protected"


# ---------------------------------------------------------------------------
# Popup warning  (shown in the interactive desktop session)
# ---------------------------------------------------------------------------

def _get_active_session_id() -> int:
    """
    Return the session ID of the currently active interactive user.
    Returns -1 if no active session is found.
    """
    try:
        WTS_CURRENT_SERVER_HANDLE = 0
        # WTSEnumerateSessions
        pSessionInfo = ctypes.c_void_p()
        count = ctypes.c_ulong(0)
        if not ctypes.windll.wtsapi32.WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE, 0, 1,
            ctypes.byref(pSessionInfo), ctypes.byref(count)
        ):
            return -1

        # Each WTS_SESSION_INFO: DWORD SessionId, LPWSTR pWinStationName, WTS_CONNECTSTATE_CLASS State
        class WTS_SESSION_INFO(ctypes.Structure):
            _fields_ = [
                ("SessionId",      ctypes.wintypes.DWORD),
                ("pWinStationName",ctypes.c_wchar_p),
                ("State",          ctypes.c_int),
            ]

        WTSActive = 0
        sessions = ctypes.cast(pSessionInfo, ctypes.POINTER(WTS_SESSION_INFO))
        active_id = -1
        for i in range(count.value):
            if sessions[i].State == WTSActive:
                active_id = sessions[i].SessionId
                break

        ctypes.windll.wtsapi32.WTSFreeMemory(pSessionInfo)
        return active_id
    except Exception as exc:
        log.debug("Could not get active session ID: %s", exc)
        return -1


def _show_warning_popup(drive_letter: str) -> None:
    """
    Display a warning MessageBox in the active user's interactive session.

    Services run as SYSTEM (session 0) and cannot directly call MessageBoxW
    on the user's desktop. We use WTSSendMessage which crosses session
    boundaries correctly — it sends the dialog to whatever session is
    currently active (the logged-in user's screen).
    """
    message = (
        f"⚠  Unencrypted USB Drive Detected\n\n"
        f"Drive:   {drive_letter}\n"
        f"Status:  NOT protected by BitLocker\n\n"
        f"This drive does not meet the security policy.\n"
        f"It will be ejected automatically.\n\n"
        f"Please use a BitLocker-encrypted drive."
    )
    title = _MB_TITLE

    def _send() -> None:
        try:
            session_id = _get_active_session_id()
            if session_id == -1:
                log.warning("No active user session found – popup cannot be shown.")
                return

            WTS_CURRENT_SERVER_HANDLE = 0
            MB_OK          = 0x00000000
            MB_ICONWARNING = 0x00000030
            MB_SYSTEMMODAL = 0x00001000
            flags = MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL

            response = ctypes.wintypes.DWORD(0)
            result = ctypes.windll.wtsapi32.WTSSendMessageW(
                WTS_CURRENT_SERVER_HANDLE,
                ctypes.wintypes.DWORD(session_id),
                title,
                ctypes.wintypes.DWORD(len(title) * 2),
                message,
                ctypes.wintypes.DWORD(len(message) * 2),
                ctypes.wintypes.DWORD(flags),
                ctypes.wintypes.DWORD(30),   # timeout seconds (0 = wait forever)
                ctypes.byref(response),
                ctypes.wintypes.BOOL(False),
            )
            if result:
                log.info("Warning popup shown to session %d for drive %s", session_id, drive_letter)
            else:
                err = ctypes.windll.kernel32.GetLastError()
                log.warning("WTSSendMessage failed (err %d) – trying fallback MessageBoxW", err)
                # Fallback: try plain MessageBoxW (works if session 0 isolation is off)
                ctypes.windll.user32.MessageBoxW(0, message, title, flags)
        except Exception as exc:
            log.error("Failed to show popup for %s: %s", drive_letter, exc)

    # Run in a daemon thread so the service loop is never blocked by the dialog
    t = threading.Thread(target=_send, daemon=True)
    t.start()
    log.info("Warning popup thread launched for %s", drive_letter)


# ---------------------------------------------------------------------------
# Drive ejection
# ---------------------------------------------------------------------------

def _eject_drive(drive_letter: str) -> bool:
    """
    Eject *drive_letter* using a diskpart script.
    Returns True on success, False on failure.
    """
    # Normalize: strip trailing backslash, ensure colon
    dl = drive_letter.rstrip("\\").rstrip("/")
    if not dl.endswith(":"):
        dl = dl + ":"

    log.info("Attempting to eject drive %s …", dl)

    # ---- Method 1: DeviceIoControl IOCTL_STORAGE_EJECT_MEDIA ---------------
    success = _eject_via_ioctl(dl)
    if success:
        log.info("Drive %s ejected successfully (IOCTL method)", dl)
        return True

    # ---- Method 2: diskpart script fallback --------------------------------
    log.warning("IOCTL eject failed for %s, trying diskpart …", dl)
    success = _eject_via_diskpart(dl)
    if success:
        log.info("Drive %s ejected successfully (diskpart method)", dl)
        return True

    log.error("All eject methods failed for %s", dl)
    return False


def _eject_via_ioctl(drive_letter: str) -> bool:
    """
    Use Win32 DeviceIoControl to lock + eject the volume.
    drive_letter must be like 'E:'
    """
    GENERIC_READ            = 0x80000000
    GENERIC_WRITE           = 0x40000000
    FILE_SHARE_READ         = 0x00000001
    FILE_SHARE_WRITE        = 0x00000002
    OPEN_EXISTING           = 3
    FSCTL_LOCK_VOLUME       = 0x00090018
    FSCTL_DISMOUNT_VOLUME   = 0x00090020
    IOCTL_STORAGE_EJECT_MEDIA = 0x002D4808
    INVALID_HANDLE_VALUE    = ctypes.c_void_p(-1).value

    vol_path = f"\\\\.\\{drive_letter}"
    try:
        handle = ctypes.windll.kernel32.CreateFileW(
            vol_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None,
        )
        if handle == INVALID_HANDLE_VALUE:
            log.debug("IOCTL: CreateFile failed for %s (err %s)", vol_path,
                      ctypes.windll.kernel32.GetLastError())
            return False

        bytes_returned = ctypes.wintypes.DWORD(0)

        # Lock
        ctypes.windll.kernel32.DeviceIoControl(
            handle, FSCTL_LOCK_VOLUME, None, 0, None, 0,
            ctypes.byref(bytes_returned), None,
        )
        # Dismount
        ctypes.windll.kernel32.DeviceIoControl(
            handle, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0,
            ctypes.byref(bytes_returned), None,
        )
        # Eject
        result = ctypes.windll.kernel32.DeviceIoControl(
            handle, IOCTL_STORAGE_EJECT_MEDIA, None, 0, None, 0,
            ctypes.byref(bytes_returned), None,
        )
        ctypes.windll.kernel32.CloseHandle(handle)
        return bool(result)
    except Exception as exc:
        log.debug("IOCTL eject exception for %s: %s", drive_letter, exc)
        return False


def _eject_via_diskpart(drive_letter: str) -> bool:
    """
    Offline the disk via diskpart as a last resort.
    """
    script = (
        f"select volume {drive_letter.rstrip(':')}\n"
        f"offline volume noerr\n"
    )
    script_path = LOG_DIR / "_eject_tmp.txt"
    try:
        script_path.write_text(script, encoding="utf-8")
        result = subprocess.run(
            ["diskpart", "/s", str(script_path)],
            capture_output=True, timeout=15,
        )
        script_path.unlink(missing_ok=True)
        return result.returncode == 0
    except Exception as exc:
        log.debug("diskpart eject exception: %s", exc)
        return False


# ---------------------------------------------------------------------------
# USB event handler  (called from the WMI monitor thread)
# ---------------------------------------------------------------------------

def handle_usb_insert(drive_letter: str) -> None:
    """
    Core policy logic: called every time a new USB volume appears.
    """
    log.info("=== USB INSERT detected  →  drive %s ===", drive_letter)

    bitlocker_status = _get_bitlocker_status(drive_letter)

    if bitlocker_status == "Protected":
        log.info("Drive %s is BitLocker-PROTECTED – allowed, no action taken.", drive_letter)
        _write_history("INSERT", drive_letter, bitlocker_status, "Allowed")
        return

    # Not encrypted (or unknown after retries) – warn then eject
    log.warning("Drive %s is NOT encrypted by BitLocker – enforcing policy.", drive_letter)
    _show_warning_popup(drive_letter)

    # Small delay so the popup is visible before the drive disappears
    time.sleep(2)

    ejected = _eject_drive(drive_letter)
    if ejected:
        log.info("Drive %s was ejected successfully.", drive_letter)
        _write_history("INSERT", drive_letter, bitlocker_status, "Ejected")
    else:
        log.error("Drive %s could NOT be ejected – manual intervention required.", drive_letter)
        _write_history("INSERT", drive_letter, bitlocker_status, "EjectFailed")


def handle_usb_remove(drive_letter: str) -> None:
    log.info("=== USB REMOVE detected  →  drive %s ===", drive_letter)
    # Drive is already gone so we can't query it — log what we know
    _write_history("REMOVE", drive_letter, "N/A", "Removed")


# ---------------------------------------------------------------------------
# WMI monitor thread  (event-driven, continuous)
# ---------------------------------------------------------------------------

class USBMonitorThread(threading.Thread):
    """
    Runs in the background inside the service process.
    Uses WMI __InstanceCreationEvent on Win32_LogicalDisk to detect USB
    volumes being attached.  Restarts itself automatically on WMI errors
    so that monitoring is truly continuous.
    """

    def __init__(self, stop_event: threading.Event):
        super().__init__(name="USBMonitorThread", daemon=True)
        self._stop = stop_event

    def run(self) -> None:
        log.info("USBMonitorThread started – listening for USB events …")
        # REQUIRED: WMI needs COM initialized on every thread that uses it
        pythoncom.CoInitialize()
        try:
            while not self._stop.is_set():
                try:
                    self._monitor_loop()
                except Exception as exc:
                    if self._stop.is_set():
                        break
                    log.error("WMI monitor loop crashed: %s – restarting in %ss",
                              exc, WMI_RESTART_DELAY)
                    time.sleep(WMI_RESTART_DELAY)
        finally:
            pythoncom.CoUninitialize()
        log.info("USBMonitorThread stopped.")

    def _monitor_loop(self) -> None:
        """
        Inner loop – blocks on WMI event notifications.
        Separate from run() so that exceptions bubble up cleanly for restart.
        """
        c = wmi.WMI()

        # Watch for new logical disk arrivals
        insert_watcher = c.Win32_LogicalDisk.watch_for(
            notification_type="Creation",
            delay_secs=1,
        )
        # Watch for logical disk removals
        remove_watcher = c.Win32_LogicalDisk.watch_for(
            notification_type="Deletion",
            delay_secs=1,
        )

        log.debug("WMI watchers registered (insert + remove) – entering event loop")

        while not self._stop.is_set():
            # Check INSERT watcher
            try:
                disk = insert_watcher(timeout_ms=1000)
                if disk is not None:
                    drive_letter = getattr(disk, "DeviceID", None) or getattr(disk, "Name", None)
                    drive_type   = getattr(disk, "DriveType", None)
                    log.debug("Win32_LogicalDisk CREATE event: letter=%s type=%s",
                              drive_letter, drive_type)
                    if drive_letter and drive_type in (2, 3):
                        try:
                            handle_usb_insert(drive_letter)
                        except Exception as exc:
                            log.error("Error handling insert for %s: %s", drive_letter, exc)
            except wmi.x_wmi_timed_out:
                pass
            except Exception:
                raise

            if self._stop.is_set():
                break

            # Check REMOVE watcher
            try:
                disk = remove_watcher(timeout_ms=1000)
                if disk is not None:
                    drive_letter = getattr(disk, "DeviceID", None) or getattr(disk, "Name", None)
                    drive_type   = getattr(disk, "DriveType", None)
                    log.debug("Win32_LogicalDisk DELETE event: letter=%s type=%s",
                              drive_letter, drive_type)
                    if drive_letter and drive_type in (2, 3):
                        try:
                            handle_usb_remove(drive_letter)
                        except Exception as exc:
                            log.error("Error handling remove for %s: %s", drive_letter, exc)
            except wmi.x_wmi_timed_out:
                pass
            except Exception:
                raise


# ---------------------------------------------------------------------------
# Windows Service class
# ---------------------------------------------------------------------------

class USBGuardService(win32serviceutil.ServiceFramework):
    _svc_name_        = SERVICE_NAME
    _svc_display_name_= SERVICE_DISPLAY
    _svc_description_ = SERVICE_DESC

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_event   = win32event.CreateEvent(None, 0, 0, None)
        self._thread_stop  = threading.Event()
        self._monitor      = None
        log.info("USBGuardService __init__ called")

    # ------------------------------------------------------------------
    def SvcStop(self):
        log.info("Service stop requested.")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._thread_stop.set()
        win32event.SetEvent(self._stop_event)

    # ------------------------------------------------------------------
    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        log.info("=" * 60)
        log.info("USBGuard Service STARTED  –  %s", datetime.now().isoformat())
        log.info("Log file: %s", LOG_FILE)
        log.info("=" * 60)

        # Start the USB monitor thread
        self._monitor = USBMonitorThread(self._thread_stop)
        self._monitor.start()

        # Block here until stop is requested
        win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)

        # Clean up
        self._thread_stop.set()
        if self._monitor and self._monitor.is_alive():
            self._monitor.join(timeout=10)

        log.info("USBGuard Service STOPPED  –  %s", datetime.now().isoformat())
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin() -> None:
    """Re-launch this same EXE with admin rights via UAC prompt and exit."""
    # ShellExecuteW with "runas" triggers the UAC elevation dialog
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(f'"{a}"' for a in sys.argv), None, 1
    )
    sys.exit(0)


def _msgbox(title: str, message: str, style: int = 0x00000040) -> int:
    """Show a simple Windows MessageBox. Returns the button pressed."""
    return ctypes.windll.user32.MessageBoxW(0, message, title, style)


def _auto_install() -> None:
    """
    Silent auto-installer — called when the EXE is double-clicked.

    Flow:
      1. If not admin  → ask user → relaunch with UAC elevation
      2. If already installed + running  → tell user, done
      3. If already installed but stopped → start it, tell user
      4. Not installed → install + set auto-start + start → tell user
    """
    MB_OK            = 0x00000000
    MB_OKCANCEL      = 0x00000001
    MB_ICONINFO      = 0x00000040
    MB_ICONWARNING   = 0x00000030
    MB_ICONERROR     = 0x00000010

    TITLE = "USB Guard – Installer"

    # ── Step 1: ensure we have admin rights ──────────────────────────────────
    if not _is_admin():
        answer = ctypes.windll.user32.MessageBoxW(
            0,
            "USB Guard needs administrator rights to install.\n\n"
            "Click OK to continue with elevated privileges.",
            TITLE,
            MB_OKCANCEL | MB_ICONWARNING,
        )
        if answer == 1:   # OK clicked
            _relaunch_as_admin()
        sys.exit(0)

    # ── Step 2: check current service state ──────────────────────────────────
    try:
        status_result = subprocess.run(
            ["sc", "query", SERVICE_NAME],
            capture_output=True, text=True
        )
        already_installed = "does not exist" not in status_result.stdout and \
                            status_result.returncode != 1060
        already_running   = "RUNNING" in status_result.stdout
    except Exception:
        already_installed = False
        already_running   = False

    # ── Already running ───────────────────────────────────────────────────────
    if already_installed and already_running:
        _msgbox(
            TITLE,
            "USB Guard is already installed and running.\n\n"
            "Your PC is protected.",
            MB_OK | MB_ICONINFO,
        )
        return

    # ── Installed but stopped — just start it ────────────────────────────────
    if already_installed and not already_running:
        try:
            subprocess.run([sys.executable, "start"], check=True, capture_output=True)
            _msgbox(
                TITLE,
                "USB Guard service has been started successfully.\n\n"
                "Your PC is now protected.",
                MB_OK | MB_ICONINFO,
            )
        except Exception as exc:
            _msgbox(TITLE, f"Failed to start service:\n{exc}", MB_OK | MB_ICONERROR)
        return

    # ── Fresh install ─────────────────────────────────────────────────────────
    exe = sys.executable

    steps = [
        ([exe, "install"],                        "Installing service…"),
        (["sc", "config", SERVICE_NAME,
          "start=", "auto"],                      "Setting auto-start on boot…"),
        ([exe, "start"],                          "Starting service…"),
    ]

    for cmd, desc in steps:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                _msgbox(
                    TITLE,
                    f"Installation failed at step:\n{desc}\n\n"
                    f"Error:\n{result.stderr or result.stdout}",
                    MB_OK | MB_ICONERROR,
                )
                return
        except Exception as exc:
            _msgbox(TITLE, f"Installation error:\n{exc}", MB_OK | MB_ICONERROR)
            return

    # ── Success ───────────────────────────────────────────────────────────────
    _msgbox(
        TITLE,
        "USB Guard installed successfully!\n\n"
        "The service is now running and will start automatically on every boot.\n\n"
        "What happens:\n"
        "  - Unencrypted USB inserted  →  Warning + auto eject\n"
        "  - BitLocker USB inserted    →  Allowed normally",
        MB_OK | MB_ICONINFO,
    )


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No arguments = either SCM is launching the service,
        # or the user double-clicked the EXE.
        # Try SCM first; on error 1063 (not started by SCM) → run auto-installer.
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(USBGuardService)
            servicemanager.StartServiceCtrlDispatcher()
        except win32service.error as exc:
            if exc.winerror == 1063:
                # Not launched by SCM — user double-clicked → auto-install
                _auto_install()
            else:
                raise
    else:
        # Command-line usage: install / start / stop / remove / debug
        win32serviceutil.HandleCommandLine(USBGuardService)
