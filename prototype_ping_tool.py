import tkinter as tk
from tkinter import filedialog
import pandas as pd
import tkinter.messagebox as messagebox
import subprocess #Para usar CMD
import re
from pandastable import Table
import socket
import copy
from PIL import ImageTk, Image
import base64
import io
#SANTIAGOPALACIOSDESARROLLO = ESTA APP
#---------------------------------------------VARIABLES------------------------------------------------
#------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------

# Variable global para guardar la imagen
imagen_fondo = None

#Datos para el filtro
dato_filtrados = []
incidentes_filtrados = []
IPs_filtradas = []

# Variable global para almacenar la función hija
abrir_ventana_secundaria_aux = None
#diccionario_dispositivos = {}
#Lista para los dispositivos que responden
lista_dns_responden = []
lista_ips_responden = []
dispositivos_responden = []
#diccionario_dispositivos_responden = {}

#Lista de dispositivos que no tienen IP
dispositivos_no_tienen_IP = []

#Lista dispositivos no responden
dispositivos_no_responden = []

#---------------------------------------------FUNCIONES------------------------------------------------
#------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------

#Funcion de subir archivos
def subir_archivo():
    # Abrir cuadro de diálogo para seleccionar archivo
    
    #limpio la lista de los AP filtrados
    dato_filtrados.clear()
    IPs_filtradas.clear()
    dispositivos_responden.clear()
    #diccionario_dispositivos_responden.clear()
    dispositivos_no_tienen_IP.clear()
    dispositivos_no_responden.clear()
    incidentes_filtrados.clear()
    lista_dns_responden.clear()
    lista_ips_responden.clear()
    

    ruta_archivo = filedialog.askopenfilename(filetypes=[("Archivos Excel", "*.xlsx"), ("Archivos CSV", "*.csv")])
    
    
    # Leer el archivo seleccionado usando pandas
    if ruta_archivo:
        datos = pd.read_excel(ruta_archivo) if ruta_archivo.endswith(".xlsx") else pd.read_csv(ruta_archivo)

        # Extraer los valores de una columna en una lista excel
        if ruta_archivo.endswith(".xlsx"): 
            #columna_EXCEL = datos['Short description']
            columna_EXCEL = datos['Description']
            columna_incidentes_aps = datos['Number'].to_list()
            lista_dispositivos = columna_EXCEL.tolist()
            
        else: 
            #columna_CSV = datos['short_description']
            columna_CSV = datos['description']
            columna_incidentes_aps =datos['number'].to_list()
            lista_dispositivos = columna_CSV.tolist()

        
        filtrado_dispositivos(lista_dispositivos,columna_incidentes_aps)
        
            #Ventana datos de tickets
    def abrir_ventana_secundaria():
        # Crear una ventana secundaria.
        #print(datos)
        try:
            if datos is not None and isinstance(datos,pd.DataFrame):
                ventana_secundaria = tk.Toplevel()
                ventana_secundaria.title("Incidents - tickets")
                
                # Crear la tabla editable
                tabla = Table(ventana_secundaria, dataframe=datos)
                tabla.config(width=800,height=600)
                tabla.show()

                # Mostrar la ventana secundaria
                ventana_secundaria.mainloop()
        except:
            
            messagebox.showwarning("Incorrect or invalid file", "please upload a valid file!")
            

    global abrir_ventana_secundaria_aux
    abrir_ventana_secundaria_aux = abrir_ventana_secundaria
    abrir_ventana_secundaria()



def filtrado_dispositivos(lista_dispositivos,columna_incidentes_aps):
    #dato_filtrados = []
    #Recorremos toda la columna de descripcion buscando el nombre del AP
    
    for pos,val in enumerate(lista_dispositivos):
        lista_incidente_aux = val.split(" ")
        
        #print("MIRA ACA*********")
        try:
            if lista_incidente_aux.index("Name:") or lista_incidente_aux.index("IP:"):
                #Sepraramos todo por todo lo que tenga dos puntos
                lista_incidente = val.split(":")
                for pos_esp,valor_esp in enumerate(lista_incidente):
                    if pos_esp == 2:
                        #Tomamos el nombre del dispositivo que nos interesa
                        nombre_de_direccion_ip = valor_esp.split()[0]
                        #print("posicion {}: {}".format(pos,nombre_de_direccion_ip))
                        dato_filtrados.append(nombre_de_direccion_ip)
                        lista_datos_filtrados(dato_filtrados)
                    
                    if pos_esp == 3:
                        device_ip = valor_esp.split()[0]
                        if device_ip == "awampAPEthMAC":
                            device_ip = "Unknown IP address"
                        IPs_filtradas.append(device_ip)
                        lista_ips_filtradas(IPs_filtradas)
                        #print(device_ip)
        except ValueError as ve:
            dato_filtrados.append("--DNS Unavailable-- ")
            lista_datos_filtrados(dato_filtrados)
            IPs_filtradas.append("--IP Unavailable--")
            lista_ips_filtradas(IPs_filtradas)
            print("---information not available---")
            

        #Sepraramos todo por todo lo que tenga dos puntos
        #lista_incidente = val.split(":")
        
        #print(val)


        #print("poscion {}: {}".format(pos,lista_incidente))


    for val in columna_incidentes_aps:
        incidentes_filtrados.append(val)
        #print(incidentes_filtrados)
        lista_incidentes(incidentes_filtrados)
                
    
def ping_devices():

    datos_ping = copy.deepcopy(lista_datos_filtrados(dato_filtrados))
    datos_incidentes = copy.deepcopy(lista_incidentes(incidentes_filtrados))
    datos_ip = copy.deepcopy(lista_ips_filtradas(IPs_filtradas))

    #print(datos_ping,datos_incidentes,datos_ip)

    # Actualizar la ventana con los resultados del ping
    
    ventana_ping = tk.Toplevel()
    ventana_ping.title("PING IN PROGESS DO NOT CLOSE THIS WINDOW...")
    #ventana_ping.geometry("800x700")
    #frame_ping.config(padx=30,pady=30)

    frame_ping = tk.Frame(ventana_ping)
    frame_ping.config(padx=10,pady=10,background="blue")


    # Crear el label para mostrar los datos
    label = tk.Text(frame_ping,state=tk.DISABLED)
    label.pack(side="left",padx=20,pady=20)
    label.insert(tk.END,"Pinging Devices... \n\n")
    label.config(state=tk.NORMAL)

    def force_stop():
        ventana_ping.destroy()
        messagebox.showerror(title="Status",message="The process has been cancelled")

    def good_results():
        print('---------------1')
        # Crear la ventana datos lista
        ventana_secundaria_good_results = tk.Toplevel()
        ventana_secundaria_good_results.title("ping-responsive devices (results) ")
        
        #Crear un Frame
        cuadro_texto = tk.Frame(ventana_secundaria_good_results,bg="green")

        # Crear un widget de Text para mostrar los datos
        text_widget = tk.Text(cuadro_texto,background="white",fg="black")
        text_widget.pack(side="top",padx=30,pady=30)
        text_widget.config(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)

        print("\n*** THE FOLLOWING DEVICES RESPOND ***")
        # Recorrer la lista de valores y agregar los pares clave-valor al diccionario avanza de 2 en 2 posiciones
        for val in range(0, len(dispositivos_responden),3):
            inc = dispositivos_responden[val]
            ap = dispositivos_responden[val + 1]
            ip = dispositivos_responden[val + 2]
            #diccionario_dispositivos_responden[dispositivos_responden[i]] = dispositivos_responden[i+1]

        # Imprimir RESULTADOS
        # Insertar los datos en el widget de Text
        #print("\n*** LOS SIGUIENTES DISPOSITIVOS RESPONDEN ***")
        #for nombre_dns,ip in diccionario_dispositivos_responden.items():
            print("{} || {} : {}".format(inc,ap,ip))
            text_widget.insert(tk.END,str("{} || {} : {}".format(inc,ap,ip)) + "\n")
        
        # Deshabilitar la edición del widget de Text
        text_widget.config(state=tk.DISABLED)
        cuadro_texto.pack()
        ventana_secundaria_good_results.mainloop()

    def good_results_ips_dns():
        print('---------------2')
        # Crear la ventana datos lista
        ventana_secundaria_good_results = tk.Toplevel()
        ventana_secundaria_good_results.title("ping-responsive devices (results) ")
        
        #Crear un Frame
        cuadro_texto_1 = tk.Frame(ventana_secundaria_good_results,bg="green")
        cuadro_texto_2 = tk.Frame(ventana_secundaria_good_results,bg="green")

        # Crear un widget de Text para mostrar los datos
        text_widget_1 = tk.Text(cuadro_texto_1,background="white",fg="black")
        text_widget_1.pack(side="top",padx=20,pady=20)
        text_widget_1.config(state=tk.NORMAL)
        text_widget_1.delete("1.0", tk.END)
        text_widget_1.insert(tk.END,"\n*** THE FOLLOWING DNS RESPOND ***\n\n")

        # Crear un widget de Text para mostrar los datos
        text_widget_2 = tk.Text(cuadro_texto_2,background="white",fg="black")
        text_widget_2.pack(side="top",padx=20,pady=20)
        text_widget_2.config(state=tk.NORMAL)
        text_widget_2.delete("1.0", tk.END)
        text_widget_2.insert(tk.END,"\n*** THE FOLLOWING IPs REPLY ***\n\n")

        print("\n*** THE FOLLOWING DNS RESPOND ***")
        # Recorrer la lista de valores y agregar los pares clave-valor al diccionario avanza de 2 en 2 posiciones
        for val in range(0, len(lista_dns_responden),3):
            inc = lista_dns_responden[val]
            ap = lista_dns_responden[val + 1]
            ip = lista_dns_responden[val + 2]
            print("{} || {} : {}".format(inc,ap,ip))
            text_widget_1.insert(tk.END,str("{} || {}: {}".format(inc,ap,ip)) + "\n")

        # Deshabilitar la edición del widget de Text
        text_widget_1.config(state=tk.DISABLED)

        print("\n*** THE FOLLOWING IPs REPLY  ***")
        # Recorrer la lista de valores y agregar los pares clave-valor al diccionario avanza de 2 en 2 posiciones
        for val in range(0, len(lista_ips_responden),3):
            inc = lista_ips_responden[val]
            ap = lista_ips_responden[val + 1]
            ip = lista_ips_responden[val + 2]
            print("{} || {} : {}".format(inc,ap,ip))
            text_widget_2.insert(tk.END,str("{} || {} : {}".format(inc,ap,ip)) + "\n")

        # Deshabilitar la edición del widget de Text
        text_widget_2.config(state=tk.DISABLED)
        
        cuadro_texto_1.pack(side="top",padx=10,pady=10)
        cuadro_texto_2.pack(side="top",padx=10,pady=10)
        ventana_secundaria_good_results.mainloop()

    def bad_results():
        print('---------------3')
        # Crear la ventana datos lista
        ventana_secundaria_bad_results = tk.Toplevel()
        ventana_secundaria_bad_results.title("Devices not responding to ping (results) ")
        
        #Crear un Frame
        cuadro_texto = tk.Frame(ventana_secundaria_bad_results,bg="red")

        # Crear un widget de Text para mostrar los datos
        text_widget = tk.Text(cuadro_texto,background="white",fg="black")
        text_widget.pack(side="top",padx=30,pady=30)
        text_widget.config(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)

        print("\n*** THE FOLLOWING DEVICES ARE NOT RESPONDING ***")
        for val in range(0, len(dispositivos_no_responden), 3):
            inc = dispositivos_no_responden[val]
            ap = dispositivos_no_responden[val + 1]
            ip = dispositivos_no_responden[val + 2]
        #for pos,val in enumerate(dispositivos_no_responden):
            print(str("{} || {} : {}".format(inc,ap,ip)))
            text_widget.insert(tk.END,str("{} || {} : {}".format(inc,ap,ip)) + "\n") 

        cuadro_texto.pack()
        ventana_secundaria_bad_results.mainloop()

    def results_ip_not_assigned ():
        print('---------------4')
        # Crear la ventana datos lista
        ventana_secundaria_ip_not_assigned = tk.Toplevel()
        ventana_secundaria_ip_not_assigned.title("Devices that do not have an assigned IP (results) ")
        
        #Crear un Frame
        cuadro_texto = tk.Frame(ventana_secundaria_ip_not_assigned,bg="purple")

        # Crear un widget de Text para mostrar los datos
        text_widget = tk.Text(cuadro_texto,background="white",fg="black")
        text_widget.pack(side="top",padx=30,pady=30)
        text_widget.config(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)
        print("\n*** THE FOLLOWING DEVICES DO NOT HAVE AN IP ***")
        for val in range(0, len(dispositivos_no_tienen_IP), 2):
            inc = dispositivos_no_tienen_IP[val]
            ap = dispositivos_no_tienen_IP[val + 1]
        #for pos,val in enumerate(dispositivos_no_tienen_IP):
            print("{} || {}".format(inc,ap))
            text_widget.insert(tk.END,str("{} || {}".format(inc,ap)) + "\n")
        
        cuadro_texto.pack()
        ventana_secundaria_ip_not_assigned.mainloop()

    def pingin_devices():
        bflag = 1
        check_dns = 0
        #mientras la lista no este vacia iterar
        while datos_ping:
            #for pos,nombre_de_direccion_ip in enumerate(datos_ping):
            for incidente,nombre_de_direccion_ip,ip_device in zip(datos_incidentes,datos_ping,datos_ip):
                print("{} {} : {}".format(incidente,nombre_de_direccion_ip,ip_device))
                # Ejecutamos el comando ping para el DNS y validar que si este funcionando
                #resultado_DNS = subprocess.run(['ping', '-n', '2', nombre_de_direccion_ip], capture_output=True)
                resultado_DNS = subprocess.Popen(["ping", "-n", "4", nombre_de_direccion_ip], stdout=subprocess.PIPE, universal_newlines=True)
                print(resultado_DNS)

                #resultado_DNS.stdout.close()

                # Agregar los resultados obtenidos a la ventana
                label.config(state=tk.NORMAL)
                label.insert(tk.END, f"--- {nombre_de_direccion_ip} ---\n")
                for linea in resultado_DNS.stdout:
                    label.insert(tk.END, linea)
                    #Valida ping DNS
                    if "Tiempo" in linea or "times" in linea:
                        check_dns = 1
                label.insert(tk.END, "\n\n")
                label.config(state=tk.DISABLED)

                label.see(tk.END)  # Desplazar la vista hacia abajo para mostrar los nuevos datos
                resultado_DNS.stdout.close() 
                
                try:
                    #Asignamos variables a la IP
                    if ip_device  == "Unknown IP address":
                        direccion_ip = socket.gethostbyname(nombre_de_direccion_ip)
                        print("The IP address of {} is: {}".format(nombre_de_direccion_ip,direccion_ip))
                        print("Pinging IP now")
                        #Hacemos un Ping a la IP para verificar que definitivamente esta funcionando
                        resultado_ip = subprocess.run(['ping', '-n', '4', direccion_ip], capture_output=True)
                    else:
                        resultado_ip = subprocess.run(['ping', '-n', '4', str(ip_device)], capture_output=True)

                    #Valida ping DNS
                    if check_dns == 1:
                        #No viene en la lista una IP
                        if ip_device == "Unknown IP address":
                            #lista_dns_responden.extend([incidente,nombre_de_direccion_ip,direccion_ip])
                            print("No packet loss in DNS")
                        else:
                            #SI hay en la lista una IP
                            #lista_dns_responden.extend([incidente,nombre_de_direccion_ip,ip_device])
                            print("No packet loss in DNS")

                    #Valida ping IP
                    if resultado_ip.returncode == 0:
                        if ip_device == "Unknown IP address":
                            #lista_ips_responden.extend([incidente,nombre_de_direccion_ip,direccion_ip])
                            print("No packet loss in the IP")
                        else:
                            #lista_ips_responden.extend([incidente,nombre_de_direccion_ip,ip_device])
                            print("No packet loss in the IP")
                    #si la IP funciona se guarda en una lista aparte
                    if resultado_ip.returncode == 0 and check_dns == 1:
                        if ip_device == "Unknown IP address":
                            dispositivos_responden.extend([incidente,nombre_de_direccion_ip,direccion_ip])
                            print("{} The IP address of {} is {} RESPOND".format(incidente,nombre_de_direccion_ip,direccion_ip))
                        else:
                            dispositivos_responden.extend([incidente,nombre_de_direccion_ip,ip_device])
                            print("{} The IP address of {} is {} RESPOND".format(incidente,nombre_de_direccion_ip,ip_device))
                        #check_dns = 0
                    #Si no responde IP no se guarda en la lista que respnden ambos
                    if resultado_ip.returncode != 0 and check_dns == 1:
                        if ip_device == "Unknown IP address":
                            lista_dns_responden.extend([incidente,nombre_de_direccion_ip,direccion_ip])
                            #lista_dns_responden.extend([incidente,nombre_de_direccion_ip,direccion_ip])
                            print("{} Only the DNS ({}) RESPOND and not the IP: {}".format(incidente,nombre_de_direccion_ip,direccion_ip))
                        else:
                            #dispositivos_responden.extend([incidente,nombre_de_direccion_ip,ip_device])
                            lista_dns_responden.extend([incidente,nombre_de_direccion_ip,ip_device])
                            print("{} Only the DNS ({}) RESPOND and not the IP: {}".format(incidente,nombre_de_direccion_ip,ip_device))
                        #check_dns = 0
                    if resultado_ip.returncode == 0 and check_dns == 0:
                        if ip_device == "Unknown IP address":
                            lista_ips_responden.extend([incidente,nombre_de_direccion_ip,direccion_ip])
                            #lista_ips_responden.extend([incidente,direccion_ip,nombre_de_direccion_ip])
                            #dispositivos_responden.extend([incidente,nombre_de_direccion_ip,direccion_ip])
                            print("{} Only the IP: {} RESPOND and not the DNS ({})".format(incidente,direccion_ip,nombre_de_direccion_ip))
                        else:
                            #dispositivos_responden.extend([incidente,nombre_de_direccion_ip,ip_device])
                            lista_ips_responden.extend([incidente,nombre_de_direccion_ip,ip_device])
                            print("{} Only the IP: {} RESPOND and not the DNS ({})".format(incidente,ip_device,nombre_de_direccion_ip))
                        #check_dns = 0                       
                    #Dispositivos que no responden
                    if resultado_ip.returncode != 0 and check_dns == 0:
                        if ip_device == "Unknown IP address":
                            dispositivos_no_responden.extend([incidente,nombre_de_direccion_ip,direccion_ip])
                            print("{} The IP address of  {} is {} NOT RESPONSIVE".format(incidente,nombre_de_direccion_ip,direccion_ip))
                        else:
                            dispositivos_no_responden.extend([incidente,nombre_de_direccion_ip,ip_device])
                            print("{} The IP address of  {} is {} NOT RESPONSIVE".format(incidente,nombre_de_direccion_ip,ip_device))

                        #print("Se detectó pérdida de paquetes.")
                    check_dns = 0

                except socket.gaierror:
                    #Llenamos en una lista los dispositivos que no tienen IP
                    dispositivos_no_tienen_IP.extend([incidente,nombre_de_direccion_ip])
                    #dispositivos_no_tienen_IP.append(incidente)
                    #dispositivos_no_tienen_IP.append(nombre_de_direccion_ip)
                    print("{} Unable to obtain the IP address of {}".format(incidente,nombre_de_direccion_ip))
                
                resultado_DNS.stdout.close()
                datos_ping.pop(0)
                datos_incidentes.pop(0)
                datos_ip.pop(0)
                #print(datos_ping)
                #print(lista_datos_filtrados(dato_filtrados))
                ventana_ping.update()
                ventana_ping.after(2000, pingin_devices)
                frame_ping.pack()
                ventana_ping.mainloop()
                bflag = 0
                print("pasando al siguiente")

            if datos_ping  == []:
                #resultado_DNS.terminate()
                #messagebox.showinfo(title="Status",message="the process has been successfully completed")
                
                break
        if bflag == 1 :
            messagebox.showinfo(title="Status",message="The process has been successfully completed")
            bflag = 0

    good_results_button = tk.Button(frame_ping, text="SHOW RESPONDING DEVICES", command=good_results)
    good_results_button.pack(side="bottom", padx=40,pady=40)
    frame_ping.pack()

    good_results_ips_dns_button = tk.Button(frame_ping, text="SHOW SEPARATE DNS-IP RESULTS", command=good_results_ips_dns)
    good_results_ips_dns_button.pack(side="bottom", padx=40,pady=40)
    frame_ping.pack()

    bad_results_button = tk.Button(frame_ping, text="SHOW NOT RESPONDING DEVICES", command=bad_results)
    bad_results_button.pack(side="bottom", padx=40,pady=40)
    frame_ping.pack()

    results_ip_not_assigned_button = tk.Button(frame_ping, text="SHOW DEVICES THAT DOESN'T HAVE IP ASSIGNED", command=results_ip_not_assigned)
    results_ip_not_assigned_button.pack(side="bottom", padx=40,pady=40)
    frame_ping.pack()

    ping_button = tk.Button(frame_ping, text="STOP PROCESS", command=force_stop)
    ping_button.pack(side="bottom", padx=40,pady=40)
    frame_ping.pack()



    ventana_ping.update()
    pingin_devices()
    ventana_ping.mainloop()
    #ventana_ping.update()
    #mostrar_alerta ()
    
       
    print("Process completed")

def lista_incidentes(incidentes_filtrados):
    return incidentes_filtrados

def lista_datos_filtrados(dato_filtrados):
    return dato_filtrados

def lista_ips_filtradas(IPs_filtradas):
    return IPs_filtradas

def abrir_ventana_datos_filtrados():

    lista_valores_actualizada = lista_datos_filtrados(dato_filtrados)
    show_lista_incidentes = lista_incidentes(incidentes_filtrados)
    show_ips_devices = lista_ips_filtradas(IPs_filtradas)

    # Crear la ventana datos lista
    ventana_secundaria_wlan = tk.Toplevel()
    ventana_secundaria_wlan.title("FILTERED DEVICES")
    ventana_secundaria_wlan.geometry("800x570")

    #Crear un Frame
    cuadro_texto = tk.Frame(ventana_secundaria_wlan,bg="white")
    cuadro_texto.config(height=30,width=500)

    # Crear un widget de Text para mostrar los datos
    text_widget = tk.Text(cuadro_texto,background="black",fg="white",height=30,width=500)
    text_widget.pack(side="top",padx=10,pady=10)
    text_widget.config(state=tk.NORMAL)
    text_widget.delete("1.0", tk.END)

    # Insertar los datos en el widget de Text
    for numero_incidente,dispositivo, ip in zip(show_lista_incidentes,lista_valores_actualizada,show_ips_devices):
        text_widget.insert(tk.END,str("{} || {} : {}".format(numero_incidente,dispositivo,ip)) + "\n")    
        print(numero_incidente,dispositivo,ip)
    
    # Deshabilitar la edición del widget de Text
    text_widget.config(state=tk.DISABLED)

    #Boton para hacer ping
    ping_button = tk.Button(cuadro_texto, text="PING DEVICES", command=ping_devices)
    ping_button.pack(side="bottom", padx=20,pady=20)
    cuadro_texto.pack()
    ventana_secundaria_wlan.mainloop()

    #dato_filtrados = []
    #ista_valores_actualizada_auxiliar = lista_valores_actualizada[:]
    #lista_valores_actualizada.clear()
    #lista_datos_filtrados(lista_valores_actualizada_auxiliar)
    

def ajustar_imagen(event):
    # Obtener el tamaño actual de la ventana
    width = main_window.winfo_width()
    height = main_window.winfo_height()

    # Redimensionar la imagen al tamaño de la ventana
    imagen_resized = imagen_original.resize((width, height))

    # Actualizar la imagen de fondo en el widget Label
    imagen_fondo = ImageTk.PhotoImage(imagen_resized)
    label_fondo.configure(image=imagen_fondo)
    label_fondo.image = imagen_fondo  # Actualizar la referencia de la imagen

#------------------------------------------------INTERFAZ GRAFICA-----------------------------------
#------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------
#Main window of the APP
main_window = tk.Tk()
main_window.title("PING TOOL")
main_window.geometry("640x360")
# Definir la imagen en formato base64 (reemplaza el valor con tu propia imagen en formato base64)
def imagen_base():

    imagen_base64 = "/9j/4AAQSkZJRgABAQEBLAEsAAD/4QBWRXhpZgAATU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAAITAAMAAAABAAEAAAAAAAAAAAEsAAAAAQAAASwAAAAB/+0ALFBob3Rvc2hvcCAzLjAAOEJJTQQEAAAAAAAPHAFaAAMbJUccAQAAAgAEAP/hDIFodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvADw/eHBhY2tldCBiZWdpbj0n77u/JyBpZD0nVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkJz8+Cjx4OnhtcG1ldGEgeG1sbnM6eD0nYWRvYmU6bnM6bWV0YS8nIHg6eG1wdGs9J0ltYWdlOjpFeGlmVG9vbCAxMC4xMCc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczp0aWZmPSdodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyc+CiAgPHRpZmY6UmVzb2x1dGlvblVuaXQ+MjwvdGlmZjpSZXNvbHV0aW9uVW5pdD4KICA8dGlmZjpYUmVzb2x1dGlvbj4zMDAvMTwvdGlmZjpYUmVzb2x1dGlvbj4KICA8dGlmZjpZUmVzb2x1dGlvbj4zMDAvMTwvdGlmZjpZUmVzb2x1dGlvbj4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6eG1wTU09J2h0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8nPgogIDx4bXBNTTpEb2N1bWVudElEPmFkb2JlOmRvY2lkOnN0b2NrOmQ3ZTEzZWE2LTRhZWMtNDkwMi04OTk3LWNhNmYzODhkYjYzNjwveG1wTU06RG9jdW1lbnRJRD4KICA8eG1wTU06SW5zdGFuY2VJRD54bXAuaWlkOjFhMTQ3Mzg2LTFjOWItNDNmMS1iN2M4LWJmZjYyZTQwZTU5MzwveG1wTU06SW5zdGFuY2VJRD4KIDwvcmRmOkRlc2NyaXB0aW9uPgo8L3JkZjpSREY+CjwveDp4bXBtZXRhPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAo8P3hwYWNrZXQgZW5kPSd3Jz8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgBaAKAAwERAAIRAQMRAf/EABwAAAIDAQEBAQAAAAAAAAAAAAIDAQQFAAYHCP/EAEsQAAIBAwIDBAYIAwYFBAEDBQECAwAEERIhBTFBEyJRYQYUMnGBkRUjQlKhscHRM2JyBySC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"
    return imagen_base64
# Decodificar la imagen base64 y crear el objeto Image
imagen_data = base64.b64decode(imagen_base())
imagen_original = Image.open(io.BytesIO(imagen_data))

# Redimensionar la imagen al tamaño inicial de la ventana
width = main_window.winfo_screenwidth()
height = main_window.winfo_screenheight()
imagen_resized = imagen_original.resize((width, height))

# Crear un widget Label y establecer la imagen de fondo inicial
imagen_fondo = ImageTk.PhotoImage(imagen_resized)
label_fondo = tk.Label(main_window, image=imagen_fondo)
label_fondo.place(x=0, y=0, relwidth=1, relheight=1)

# Vincular el evento de cambio de tamaño de la ventana con la función de ajuste de imagen
main_window.bind("<Configure>", ajustar_imagen)

#Upload files buttom
read_button = tk.Button(main_window, text="Upload New File", command=subir_archivo)
read_button.place(x=500, y=500)
read_button.pack(side="top",padx=20,pady=20)

show_tickets_button = tk.Button(main_window, text="Show tickets", command=lambda: abrir_ventana_secundaria_aux())
show_tickets_button.place(x=-40, y=-80)
show_tickets_button.pack(side="top",padx=20,pady=20)

show_wlan_devices_button = tk.Button(main_window, text="Show filtred devices", command=abrir_ventana_datos_filtrados)
show_wlan_devices_button.place(x=-40, y=-80)
show_wlan_devices_button.pack(side="top",padx=20,pady=20)


main_window.mainloop()
#---------------------------------------------Ejecucion------------------------------------------------
#------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------
