import ctypes
import psutil

def get_ram_and_disk_info():
    # Detectar RAM usando ctypes
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    memory_status = MEMORYSTATUSEX()
    memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status))

    total_ram_gb = memory_status.ullTotalPhys / (1024**3)

    # Detectar espacio total en disco usando psutil
    total_disk_space_gb = 0
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            total_disk_space_gb += usage.total / (1024**3)
        except PermissionError:
            # Algunas particiones pueden no ser accesibles
            continue

    return total_ram_gb, total_disk_space_gb


def check_if_vm(total_ram_gb, total_disk_space_gb):
    if total_ram_gb < 8 or total_disk_space_gb < 256:
        return True
    return False


if __name__ == "__main__":
    total_ram_gb, total_disk_space_gb = get_ram_and_disk_info()
    
    print(f"Total RAM: {total_ram_gb:.2f} GB")
    print(f"Total Disk Space: {total_disk_space_gb:.2f} GB")
    
    if check_if_vm(total_ram_gb, total_disk_space_gb):
        print("El sistema tiene características similares a una máquina virtual.")
    else:
        print("El sistema parece una máquina física.")

