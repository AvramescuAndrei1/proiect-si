import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox
from database_manager import DBManager
from crypto_engine import CryptoEngine
import os, configparser

class DetailWindow(ctk.CTkToplevel):
    def __init__(self, parent, f):
        super().__init__(parent)
        self.title("Detalii DB")
        self.geometry("500x450")
        self.attributes("-topmost", True)
        txt = f"ID: {f.id}\nNume: {f.name}\nAlgoritm: {f.alg_used}\nCheie: {f.key_val}\n\nPERFORMANTA (PURE):\nFW: {f.perf_fw}\nTimp: {f.perf_t} ms\nRAM: {f.perf_m} KB\n\nDATE:\nStatus: {f.status}\nCale: {f.path}\nHash: {f.hash_val}"
        ctk.CTkLabel(self, text=txt, justify="left", wraplength=450).pack(pady=20, padx=20)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.db = DBManager()
        self.engine = CryptoEngine()
        self.load_config()
        self.title("Crypto Management")
        self.geometry("1000x600")
        self.sidebar = ctk.CTkFrame(self, width=220)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)
        self.alg_var = ctk.StringVar(value="AES-256")
        ctk.CTkOptionMenu(self.sidebar, values=["AES-256", "RSA-2048"], variable=self.alg_var).pack(pady=5)
        self.fw_var = ctk.StringVar(value="OpenSSL")
        ctk.CTkOptionMenu(self.sidebar, values=["OpenSSL", "Cryptography Lib"], variable=self.fw_var).pack(pady=5)
        ctk.CTkLabel(self.sidebar, text="Cheie Noua:").pack(pady=(10, 0))
        self.key_entry = ctk.CTkEntry(self.sidebar)
        self.key_entry.pack(pady=5, padx=10)
        ctk.CTkLabel(self.sidebar, text="Chei din DB:").pack(pady=(10, 0))
        self.key_db_var = ctk.StringVar(value="Selecteaza...")
        self.key_menu = ctk.CTkOptionMenu(self.sidebar, variable=self.key_db_var, values=["Selecteaza..."])
        self.key_menu.pack(pady=5)
        ctk.CTkButton(self.sidebar, text="Cripteaza", command=lambda: self.process("enc")).pack(pady=10)
        ctk.CTkButton(self.sidebar, text="Decripteaza", command=lambda: self.process("dec"), fg_color="green").pack(pady=10)
        self.tree = ttk.Treeview(self, columns=("ID", "Nume", "Algoritm", "Status"), show="headings")
        for c in ("ID", "Nume", "Algoritm", "Status"): self.tree.heading(c, text=c)
        self.tree.pack(expand=True, fill="both", padx=10, pady=10)
        self.tree.bind("<Double-1>", self.on_click)
        self.refresh()

    def load_config(self):
        config = configparser.ConfigParser()
        config.read('options.ini')
        self.ossl = config.get('SETTINGS', 'openssl_path', fallback='openssl')

    def refresh(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        for f in self.db.get_files(): self.tree.insert("", "end", values=(f.id, f.name, f.alg_used, f.status))
        keys = self.db.get_keys()
        if keys: self.key_menu.configure(values=keys)

    def on_click(self, event):
        item = self.tree.selection()
        if item:
            fid = self.tree.item(item, "values")[0]
            DetailWindow(self, self.db.get_file_details(fid))

    def process(self, op):
        p = filedialog.askopenfilename()
        if not p: return
        k = self.key_entry.get() if self.key_entry.get() else self.key_db_var.get()
        if k == "Selecteaza..." or not k:
            messagebox.showwarning("Eroare", "Alege o cheie!")
            return
        alg, fw = self.alg_var.get(), self.fw_var.get()
        try:
            if op == "enc": self.db.save_key(k, alg)
            if alg == "AES-256":
                if fw == "OpenSSL": out, t, m = self.engine.aes_ossl(p, k, self.ossl, op)
                else:
                    with open(p, "rb") as f: d = f.read()
                    out, t, m = self.engine.aes_lib(d, k, p, op)
            else:
                if fw == "OpenSSL": out, t, m = self.engine.rsa_ossl(p, self.ossl, op)
                else:
                    with open(p, "rb") as f: d = f.read()
                    out, t, m = self.engine.rsa_lib(d, p, op)
            status = "Criptat" if op == "enc" else "Decriptat"
            fid = self.db.add_file(os.path.basename(out), p, k, alg, status)
            self.db.add_log(fid, alg, fw, op.capitalize(), round(t, 2), round(m, 2))
            self.refresh()
            messagebox.showinfo("Succes", f"Operatiune reusita!\nTimp pur: {round(t, 2)} ms")
        except Exception as e:
            messagebox.showerror("Eroare", str(e))

if __name__ == "__main__":
    App().mainloop()