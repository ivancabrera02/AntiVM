import wmi

def get_ram_and_disk_info():
    # Crear un objeto WMI
    c = wmi.WMI()

    # Obtener información de la RAM
    total_ram_kb = sum(int(mem.Capacity) for mem in c.Win32_PhysicalMemory())
    total_ram_gb = total_ram_kb / (1024**3)

    # Obtener información del disco
    total_disk_space_bytes = sum(
        int(disk.Size) for disk in c.Win32_DiskDrive() if disk.Size
    )
    total_disk_space_gb = total_disk_space_bytes / (1024**3)

    return total_ram_gb, total_disk_space_gb


def check_if_vm(total_ram_gb, total_disk_space_gb):
    if total_ram_gb < 8 or total_disk_space_gb < 256:
        return True
    return False


if __name__ == "__main__":
    try:
        total_ram_gb, total_disk_space_gb = get_ram_and_disk_info()
        
        print(f"Total RAM: {total_ram_gb:.2f} GB")
        print(f"Total Disk Space: {total_disk_space_gb:.2f} GB")
        
        if check_if_vm(total_ram_gb, total_disk_space_gb):
            print("El sistema tiene características similares a una máquina virtual.")
        else:
            print("El sistema parece una máquina física.")
    except Exception as e:
        print(f"Error al obtener información del sistema: {e}")
