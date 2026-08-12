# sandbox_detector.py
# Простой детектор виртуальных машин и песочниц.
# Учебный проект для портфолио.

import os
import ctypes
import platform
import subprocess
import uuid

# ------------------------------------------------------------
# База сигнатур
# ------------------------------------------------------------
VM_MAC_PREFIXES = (
    "08:00:27",  # VirtualBox
    "00:05:69",  # VMware
    "00:0c:29",  # VMware
    "00:50:56",  # VMware
    "00:1c:42",  # Parallels
    "00:16:3e",  # Xen
)

SUSPICIOUS_PROCESSES = (
    "vboxservice.exe", "vboxtray.exe",
    "vmwaretray.exe", "vmwareservice.exe",
    "xenservice.exe",
    "procmon.exe", "wireshark.exe",
    "x64dbg.exe", "ollydbg.exe", "ida.exe",
    "dumpcap.exe", "fiddler.exe",
)

MIN_REAL_RAM_MB = 2048  # Минимальный правдоподобный объём ОЗУ


# ------------------------------------------------------------
# Функции проверок
# ------------------------------------------------------------
def check_mac_address():
    """Проверяет, принадлежит ли MAC-адрес известному гипервизору."""
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff)
                        for i in range(0, 48, 8)][::-1])
        for prefix in VM_MAC_PREFIXES:
            if mac.lower().startswith(prefix):
                return True
    except Exception:
        pass
    return False


def check_processes():
    """Ищет процессы-индикаторы анализа или виртуализации."""
    try:
        output = subprocess.check_output("tasklist", shell=True).decode().lower()
        for proc in SUSPICIOUS_PROCESSES:
            if proc in output:
                return True
    except Exception:
        pass
    return False


def check_ram():
    """Проверяет, не занижен ли объём ОЗУ (характерно для легковесных песочниц)."""
    try:
        kernel32 = ctypes.windll.kernel32
        mem_kb = ctypes.c_ulonglong()
        kernel32.GetPhysicallyInstalledSystemMemory(ctypes.byref(mem_kb))
        total_mb = int(mem_kb.value / 1024)
        return total_mb < MIN_REAL_RAM_MB
    except Exception:
        return False


def check_debugger():
    """Проверяет наличие отладчика через WinAPI."""
    try:
        if ctypes.windll.kernel32.IsDebuggerPresent():
            return True
    except Exception:
        pass
    return False


# ------------------------------------------------------------
# Главный блок
# ------------------------------------------------------------
if __name__ == "__main__":
    print("[*] Sandbox Detector запущен.")
    print(f"[*] Система: {platform.system()} {platform.release()}")
    print(f"[*] Имя компьютера: {platform.node()}")

    flags = 0

    if check_mac_address():
        print("[!] Обнаружен MAC-адрес виртуальной машины.")
        flags += 1

    if check_processes():
        print("[!] Найдены процессы, характерные для анализа или виртуализации.")
        flags += 1

    if check_ram():
        print("[!] Слишком мало оперативной памяти — возможно, песочница.")
        flags += 1

    if check_debugger():
        print("[!] Обнаружен отладчик.")
        flags += 1

    if flags == 0:
        print("[+] Признаков виртуальной среды не обнаружено. Похоже на реальную машину.")
    else:
        print(f"[-] Найдено {flags} признаков виртуальной среды. Запуск на ВМ или под анализом.")

    input("\nНажми Enter для выхода...")
