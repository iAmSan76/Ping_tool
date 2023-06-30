import subprocess

direccion_ip = "facebook.com"  # Dirección IP de Google

comando_ping = ["ping", "-n", "4", direccion_ip]

resultado = subprocess.Popen(comando_ping, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
salida_stdout, salida_stderr = resultado.communicate()

# Decodificar la salida en bytes a formato de texto
salida_stdout = salida_stdout.decode()

# Buscar la línea que indica el porcentaje de pérdida de paquetes
lineas = salida_stdout.split("\n")
for linea in lineas:
    if "packet loss" in linea:
        porcentaje_perdida = linea.split(",")[-1].strip()
        print("Porcentaje de pérdida de paquetes:", porcentaje_perdida)
        break

print("La inge Lady pro regaña mucho a su novio")