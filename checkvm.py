import ctypes
import time
import math

# Estructura POINT para obtener la posición del cursor
class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

# Función para obtener la posición del cursor
def get_cursor_position():
    pt = POINT()
    ctypes.windll.user32.GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y

# Función para calcular la distancia entre dos puntos
def calculate_distance(x1, y1, x2, y2):
    return math.sqrt((x2 - x1)**2 + (y2 - y1)**2)

# Función para detectar comportamiento humano en el movimiento del cursor
def detect_sandbox(threshold=5, interval=0.1, duration=10):
    """
    Detecta si el cursor está siendo movido de manera natural.
    
    threshold: Distancia mínima para considerar un movimiento significativo.
    interval: Intervalo en segundos para registrar posiciones.
    duration: Duración total en segundos del análisis.
    """
    positions = []
    start_time = time.time()

    while time.time() - start_time < duration:
        pos = get_cursor_position()
        positions.append(pos)
        time.sleep(interval)

    unnatural_movements = 0
    for i in range(1, len(positions)):
        dist = calculate_distance(*positions[i-1], *positions[i])
        if dist < threshold:
            unnatural_movements += 1

    # Determinar si es una sandbox
    if unnatural_movements / len(positions) > 0.8:
        return True
    return False


if __name__ == "__main__":
    print("Analizando movimiento del cursor...")
    if detect_sandbox():
        print("El sistema parece estar ejecutándose en un entorno de sandbox.")
    else:
        print("El movimiento del cursor parece humano.")
