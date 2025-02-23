import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
import time

class PortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner - by [Seu Nome]")
        self.root.geometry("700x450")
        self.root.configure(bg="#2b2b2b")
        self.root.resizable(False, False)

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TProgressbar", troughcolor="#3a3a3a", background="#4CAF50", thickness=20)

        self.main_frame = tk.Frame(root, bg="#2b2b2b", bd=0)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.ip_label = tk.Label(self.main_frame, text="Digite o IP ou Domínio:", bg="#2b2b2b", fg="#e0e0e0", 
                                font=("Helvetica", 14, "bold"))
        self.ip_label.pack(pady=(0, 10))

        self.ip_entry = tk.Entry(self.main_frame, width=35, font=("Helvetica", 12), bg="#3a3a3a", fg="#ffffff", 
                                insertbackground="#4CAF50", bd=0, relief="flat")
        self.ip_entry.pack(pady=(0, 15))
        self.ip_entry.configure(highlightthickness=1, highlightbackground="#4CAF50")

        self.button_frame = tk.Frame(self.main_frame, bg="#2b2b2b")
        self.button_frame.pack(pady=10)

        self.scan_button = tk.Button(self.button_frame, text="Escanear Portas", command=self.start_scan, 
                                    bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"), bd=0, 
                                    relief="flat", activebackground="#45a049", cursor="hand2")
        self.scan_button.pack(side=tk.LEFT, padx=5)
        self.scan_button.bind("<Enter>", lambda e: self.scan_button.config(bg="#45a049"))
        self.scan_button.bind("<Leave>", lambda e: self.scan_button.config(bg="#4CAF50"))

        self.stop_button = tk.Button(self.button_frame, text="Parar", command=self.stop, 
                                    bg="#f44336", fg="white", font=("Helvetica", 12, "bold"), bd=0, 
                                    relief="flat", activebackground="#d32f2f", cursor="hand2")
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.stop_button.bind("<Enter>", lambda e: self.stop_button.config(bg="#d32f2f"))
        self.stop_button.bind("<Leave>", lambda e: self.stop_button.config(bg="#f44336"))

        self.result_text = scrolledtext.ScrolledText(self.main_frame, width=60, height=15, font=("Consolas", 10), 
                                                    bg="#3a3a3a", fg="#e0e0e0", bd=0, relief="flat", 
                                                    highlightthickness=1, highlightbackground="#4CAF50")
        self.result_text.pack(pady=15)

        self.progress = ttk.Progressbar(self.main_frame, length=500, mode="determinate")
        self.progress.pack(pady=10)

        self.scanning = False

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None

    def scan_range(self, ip, start_port, end_port):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"[*] Iniciando scan em {ip} (portas {start_port}-{end_port})...\n")
        self.scanning = True
        self.scan_button.config(state="disabled")
        self.progress["maximum"] = end_port - start_port + 1
        open_ports = []

        for port in range(start_port, end_port + 1):
            if not self.scanning:
                self.result_text.insert(tk.END, "[!] Scan interrompido.\n", "error")
                break
            result = self.scan_port(ip, port)
            if result:
                open_ports.append(result)
                self.result_text.insert(tk.END, f"[+] Porta {result} aberta\n", "open")
            self.progress["value"] = port - start_port + 1
            self.root.update()

        if self.scanning:
            if open_ports:
                self.result_text.insert(tk.END, f"\n[✓] Scan concluído. Portas abertas: {', '.join(map(str, open_ports))}\n", "summary")
            else:
                self.result_text.insert(tk.END, "\n[✓] Scan concluído. Nenhuma porta aberta encontrada.\n", "summary")

        self.result_text.tag_config("open", foreground="#4CAF50")
        self.result_text.tag_config("summary", foreground="#FFD700")
        self.result_text.tag_config("error", foreground="#f44336")
        self.scanning = False
        self.scan_button.config(state="normal")

    def start_scan(self):
        ip = self.ip_entry.get()
        if not ip:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "[!] Por favor, digite um IP ou domínio válido!\n", "error")
            return

        self.progress["value"] = 0
        thread = threading.Thread(target=self.scan_range, args=(ip, 1, 1024))
        thread.start()

    def stop(self):
        self.scanning = False

def main():
    root = tk.Tk()
    app = PortScanner(root)
    root.protocol("WM_DELETE_WINDOW", lambda: [app.stop(), root.destroy()])
    root.mainloop()

if __name__ == "__main__":
    main()