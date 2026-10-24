import math, hashlib, tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# --- 1. ENGINE & CRYPTO LOGIC ---
class CryptEngine:
    @staticmethod
    def key_pad(k_str, l):
        b = k_str.encode('utf-8')
        return b.ljust(l, b'\0') if len(b) < l else b[:l]

    @staticmethod
    def get_inverses():
        return {a: x for a in range(1, 26) if math.gcd(a, 26) == 1 for x in range(1, 26) if (a * x) % 26 == 1}

    @staticmethod
    def classical(mode, algo, text, k1="3", k2="0"):
        text_clean = [c.upper() for c in text if c.isalpha()]
        if not text_clean and "Playfair" not in algo: return text
       
        if "Caesar" in algo:
            s = int(k1 or 3) if mode == 'enc' else -int(k1 or 3)
            return "".join(chr(((ord(c) - (65 if c.isupper() else 97) + s) % 26) + (65 if c.isupper() else 97)) if c.isalpha() else c for c in text).upper()
       
        elif "Multiplicative" in algo:
            a_val = int(k1)
            if mode == 'dec':
                inverses = CryptEngine.get_inverses()
                a_val = inverses.get(a_val, 1) # جلب المعكوس الضربي تلقائياً
            return "".join(chr((((ord(c) - (65 if c.isupper() else 97)) * a_val) % 26) + (65 if c.isupper() else 97)) if c.isalpha() else c for c in text).upper()
       
        elif "Affine" in algo:
            a_val, b_val = int(k1), int(k2)
            if mode == 'enc':
                return "".join(chr((((a_val * (ord(c) - 65) + b_val) % 26)) + 65) if c.isalpha() else c for c in text.upper()).upper()
            else:
                inverses = CryptEngine.get_inverses()
                a_inv = inverses.get(a_val, 1) # حساب المعكوس الضربي تلقائياً لـ a
                return "".join(chr((((a_inv * ((ord(c) - 65) - b_val)) % 26)) + 65) if c.isalpha() else c for c in text.upper()).upper()
       
        elif "Autokey" in algo:
            k_str = (k1.upper() + "".join(text_clean))[:len(text_clean)] if mode == 'enc' else k1.upper()
            res, ck = "", k_str
            for i, c in enumerate(text_clean):
                shift = ord(ck[i]) - 65
                ch = chr(((ord(c) - 65 + (shift if mode == 'enc' else -shift)) % 26) + 65)
                res += ch; ck += ch
            return res.upper()
       
        elif "Vigenère" in algo:
            ks, idx, r = k1.upper(), 0, ""
            for c in text:
                if c.isalpha():
                    b = 65 if c.isupper() else 97
                    shift = ord(ks[idx % len(ks)]) - 65
                    r += chr(((ord(c) - b + (shift if mode == 'enc' else -shift)) % 26) + b); idx += 1
                else: r += c
            return r.upper()

        elif "Playfair" in algo:
            k = k1.upper().replace('J', 'I')
            m_lets = []
            for c in k + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
                if c.isalpha() and c not in m_lets: m_lets.append(c)
            mat = [m_lets[i:i+5] for i in range(0, 25, 5)]
            pos = {mat[r][c]: (r, c) for r in range(5) for c in range(5)}
            prep = []
            if mode == 'enc':
                i = 0
                while i < len(text_clean):
                    a = text_clean[i]; b = text_clean[i+1] if i+1 < len(text_clean) else 'X'
                    if a == b: prep.extend([a, 'X']); i += 1
                    else: prep.extend([a, b]); i += 2
                if len(prep) % 2 != 0: prep.append('X')
            else: prep = text_clean
           
            res, step = "", 1 if mode == 'enc' else -1
            for i in range(0, len(prep), 2):
                r1, c1 = pos[prep[i]]; r2, c2 = pos[prep[i+1]]
                if r1 == r2: res += mat[r1][(c1 + step) % 5] + mat[r2][(c2 + step) % 5]
                elif c1 == c2: res += mat[(r1 + step) % 5][c1] + mat[(r2 + step) % 5][c2]
                else: res += mat[r1][c2] + mat[r2][c1]
            return res.upper()

# --- 2. MAIN GUI APPLICATION ---
class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title(" نظام التشفير والأمن المتكامل ")
        self.root.geometry("950x720")
        self.root.configure(bg="#EAEAEA")
       
        self.invs = CryptEngine.get_inverses()
        self.rsa_key = RSA.generate(2048)
        self.rsa_pub = PKCS1_OAEP.new(self.rsa_key.publickey())
        self.rsa_priv = PKCS1_OAEP.new(self.rsa_key)
        self.aes_cipher, self.aes_nonce = None, None

        self.setup_styles()
        self.create_header()
        self.create_tabs()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
       
        style.configure("TNotebook", background="#EAEAEA", borderwidth=0)
        style.configure("TNotebook.Tab", background="#2C3E50", foreground="white", padding=[15, 6], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#3498DB")], foreground=[("selected", "white")])

        style.configure("TCombobox", fieldbackground="white", font=("Segoe UI", 10))
        style.configure("TLabelframe", background="#EAEAEA", foreground="#2C3E50", font=("Segoe UI", 10, "bold"))
        style.configure("TLabelframe.Label", background="#EAEAEA", foreground="#16A085", font=("Segoe UI", 10, "bold"))

    def create_header(self):
        header_frame = tk.Frame(self.root, bg="#1F2A38", height=80)
        header_frame.pack(fill='x', side='top')
       
        lbl_title = tk.Label(header_frame, text="🛡️نظام التشفير والأمن المتكامل 🛡️", font=("Segoe UI", 16, "bold"), fg="#F1C40F", bg="#1F2A38")
        lbl_title.pack(pady=(12, 2))
       
        lbl_sub = tk.Label(header_frame, text="المستخدم: SWARS | AegisCipher System", font=("Segoe UI", 9), fg="#BDC3C7", bg="#1F2A38")
        lbl_sub.pack(pady=(0, 10))

    def create_tabs(self):
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill='both', expand=True, padx=15, pady=10)
       
        t1 = ttk.Frame(self.nb)
        t2 = ttk.Frame(self.nb)
        t3 = ttk.Frame(self.nb)
        t4 = ttk.Frame(self.nb)
       
        self.nb.add(t1, text="  1. الخوارزميات الكلاسيكية  ")
        self.nb.add(t2, text="  2. التشفير الحديث (AES/DES)  ")
        self.nb.add(t3, text="  3. تبادل المفاتيح (RSA)  ")
        self.nb.add(t4, text="  4. دوال الهاش  ")
       
        self.ui_classical(t1)
        self.ui_modern(t2)
        self.ui_rsa(t3)
        self.ui_hash(t4)

    # --- TAB 1: CLASSICAL ---
    def ui_classical(self, tab):
        lf1 = ttk.LabelFrame(tab, text=" [ 1 ] نوع التشفير ")
        lf1.pack(fill='x', padx=10, pady=5)
       
        f1 = tk.Frame(lf1, bg="#EAEAEA")
        f1.pack(fill='x', padx=10, pady=5)
        tk.Label(f1, text=":الخوارزمية", font=("Segoe UI", 10), bg="#EAEAEA").pack(side='right', padx=5)
        self.cbo_algo = ttk.Combobox(f1, values=["قيصر (Caesar)", "المضاعف (Multiplicative)", "الأفيني (Affine)", "المفتاح التلقائي (Autokey)", "فيجينير (Vigenère)", "بليفير (Playfair)"], state="readonly", width=35)
        self.cbo_algo.current(0)
        self.cbo_algo.pack(side='right', padx=5)
        self.cbo_algo.bind("<<ComboboxSelected>>", self.on_algo_change)
       
        lf2 = ttk.LabelFrame(tab, text=" [ 2 ] إدخال النص والمفاتيح ")
        lf2.pack(fill='x', padx=10, pady=5)
       
        f2 = tk.Frame(lf2, bg="#EAEAEA")
        f2.pack(fill='x', padx=10, pady=5)
       
        tk.Label(f2, text=":النص", font=("Segoe UI", 10), bg="#EAEAEA").grid(row=0, column=3, sticky='e', padx=5, pady=5)
        self.txt_c_in = ttk.Entry(f2, width=65, font=("Segoe UI", 10))
        self.txt_c_in.grid(row=0, column=0, columnspan=3, sticky='w', padx=5, pady=5)

        self.lbl_k1 = tk.Label(f2, text=":المفتاح 1 (a)", font=("Segoe UI", 10), bg="#EAEAEA")
        self.lbl_k1.grid(row=1, column=3, sticky='e', padx=5, pady=5)
        self.ent_k1 = ttk.Entry(f2, width=20)
        self.ent_k1.grid(row=1, column=2, sticky='e', padx=5, pady=5)
       
        self.cbo_inv = ttk.Combobox(f2, values=[f"{k}" for k in self.invs.keys()], state="readonly", width=10)
        self.cbo_inv.current(2)
       
        self.lbl_k2 = tk.Label(f2, text=":المفتاح 2 (b)", font=("Segoe UI", 10), bg="#EAEAEA")
        self.ent_k2 = ttk.Entry(f2, width=10)

        bf = tk.Frame(tab, bg="#EAEAEA")
        bf.pack(pady=5)
        tk.Button(bf, text="تشفير 🔒", bg="#D4AC0D", fg="white", font=("Segoe UI", 10, "bold"), width=12, relief="flat", command=lambda: self.run_class('enc')).pack(side='left', padx=10)
        tk.Button(bf, text="فك التشفير 🔓", bg="#7D6608", fg="white", font=("Segoe UI", 10, "bold"), width=12, relief="flat", command=lambda: self.run_class('dec')).pack(side='left', padx=10)

        lf3 = ttk.LabelFrame(tab, text=" [ 3 ] النتيجة ")
        lf3.pack(fill='both', expand=True, padx=10, pady=5)
        self.txt_c_out = scrolledtext.ScrolledText(lf3, height=8, font=("Consolas", 10))
        self.txt_c_out.pack(fill='both', expand=True, padx=5, pady=5)

    def on_algo_change(self, e=None):
        a = self.cbo_algo.get()
        self.ent_k1.grid_remove()
        self.cbo_inv.grid_remove()
        self.lbl_k2.grid_remove()
        self.ent_k2.grid_remove()
       
        if "Multiplicative" in a:
            self.cbo_inv.grid(row=1, column=2, sticky='e', padx=5, pady=5)
        elif "Affine" in a:
            self.cbo_inv.grid(row=1, column=2, sticky='e', padx=5, pady=5)
            self.lbl_k2.grid(row=1, column=1, sticky='e', padx=2, pady=5)
            self.ent_k2.grid(row=1, column=0, sticky='e', padx=5, pady=5)
        else:
            self.ent_k1.grid(row=1, column=2, sticky='e', padx=5, pady=5)

    def run_class(self, mode):
        a = self.cbo_algo.get()
        t = (self.txt_c_in.get() if mode == 'enc' else self.txt_c_out.get("1.0", tk.END)).strip()
       
        k1_val = self.cbo_inv.get() if "Multiplicative" in a or "Affine" in a else self.ent_k1.get()
        k2_val = self.ent_k2.get() if "Affine" in a else "0"
       
        if ("Affine" in a or "Multiplicative" in a) and not k1_val:
            messagebox.showwarning("تنبيه", "يرجى اختيار قيمة المفتاح a!")
            return

        res = CryptEngine.classical(mode, a, t, k1_val, k2_val)
        self.txt_c_out.delete("1.0", tk.END)
        self.txt_c_out.insert(tk.END, res.upper())

    # --- TAB 2: MODERN (AES/DES) ---
    def ui_modern(self, tab):
        lf1 = ttk.LabelFrame(tab, text=" [ 1 ] نوع التشفير ")
        lf1.pack(fill='x', padx=10, pady=5)
       
        f1 = tk.Frame(lf1, bg="#EAEAEA")
        f1.pack(fill='x', padx=10, pady=5)
        tk.Label(f1, text=":الخوارزمية", font=("Segoe UI", 10), bg="#EAEAEA").pack(side='right', padx=5)
        self.cbo_sym = ttk.Combobox(f1, values=["AES-192 ", "DES "], state="readonly", width=35)
        self.cbo_sym.current(0)
        self.cbo_sym.pack(side='right', padx=5)

        lf2 = ttk.LabelFrame(tab, text=" [ 2 ] إدخال النص والمفتاح ")
        lf2.pack(fill='x', padx=10, pady=5)
       
        f2 = tk.Frame(lf2, bg="#EAEAEA")
        f2.pack(fill='x', padx=10, pady=5)
       
        tk.Label(f2, text=":النص المطلوب", font=("Segoe UI", 10), bg="#EAEAEA").grid(row=0, column=1, sticky='e', padx=5, pady=5)
        self.txt_m_in = ttk.Entry(f2, width=65, font=("Segoe UI", 10))
        self.txt_m_in.grid(row=0, column=0, padx=5, pady=5)
       
        tk.Label(f2, text=":المفتاح السرّي", font=("Segoe UI", 10), bg="#EAEAEA").grid(row=1, column=1, sticky='e', padx=5, pady=5)
        self.txt_m_key = ttk.Entry(f2, width=65, font=("Segoe UI", 10))
        self.txt_m_key.grid(row=1, column=0, padx=5, pady=5)

        bf = tk.Frame(tab, bg="#EAEAEA")
        bf.pack(pady=5)
        tk.Button(bf, text="تشفير 🔒", bg="#D4AC0D", fg="white", font=("Segoe UI", 10, "bold"), width=12, relief="flat", command=self.run_sym_enc).pack(side='left', padx=10)
        tk.Button(bf, text="فك التشفير 🔓", bg="#7D6608", fg="white", font=("Segoe UI", 10, "bold"), width=12, relief="flat", command=self.run_sym_dec).pack(side='left', padx=10)

        lf3 = ttk.LabelFrame(tab, text=" [ 3 ] النتيجة ")
        lf3.pack(fill='both', expand=True, padx=10, pady=5)
        self.txt_m_out = scrolledtext.ScrolledText(lf3, height=8, font=("Consolas", 10))
        self.txt_m_out.pack(fill='both', expand=True, padx=5, pady=5)

    def run_sym_enc(self):
        t = self.txt_m_in.get().strip()
        k_str = self.txt_m_key.get().strip()
        a = self.cbo_sym.get()

        if not t:
            messagebox.showwarning("تنبيه", "يرجى إدخال النص المراد تشفيره!")
            return
        if not k_str:
            messagebox.showwarning("تنبيه", "يرجى إدخال المفتاح السرّي!")
            return

        if "AES" in a:
            k = CryptEngine.key_pad(k_str, 32)
            c = AES.new(k, AES.MODE_GCM)
            self.aes_cipher, self.aes_nonce = c.encrypt(t.encode()), c.nonce
            r = f"CIPHERTEXT (HEX):\n{self.aes_cipher.hex().upper()}\n\nNONCE:\n{self.aes_nonce.hex().upper()}"
        else:
            k = CryptEngine.key_pad(k_str, 8)
            r = DES.new(k, DES.MODE_ECB).encrypt(pad(t.encode(), 8)).hex().upper()
        self.txt_m_out.delete("1.0", tk.END)
        self.txt_m_out.insert(tk.END, r.upper())

    def run_sym_dec(self):
        k_str = self.txt_m_key.get().strip()
        a = self.cbo_sym.get()

        if not k_str:
            messagebox.showwarning("تنبيه", "يرجى إدخال المفتاح السرّي لفك التشفير!")
            return

        try:
            if "AES" in a:
                k = CryptEngine.key_pad(k_str, 32)
                r = AES.new(k, AES.MODE_GCM, nonce=self.aes_nonce).decrypt(self.aes_cipher).decode()
            else:
                k = CryptEngine.key_pad(k_str, 8)
                hx = self.txt_m_out.get("1.0", tk.END).strip()
                r = unpad(DES.new(k, DES.MODE_ECB).decrypt(bytes.fromhex(hx)), 8).decode()
            self.txt_m_out.delete("1.0", tk.END)
            self.txt_m_out.insert(tk.END, r)
        except Exception:
            messagebox.showerror("خطأ", "فشل فك التشفير! تحقق من صحة المفتاح والبيانات.")

    # --- TAB 3: RSA ---
    def ui_rsa(self, tab):
        lf1 = ttk.LabelFrame(tab, text=" [ 1 ] النص المراد تشفيره ")
        lf1.pack(fill='x', padx=10, pady=5)
       
        f1 = tk.Frame(lf1, bg="#EAEAEA")
        f1.pack(fill='x', padx=10, pady=5)
        tk.Label(f1, text=":مفتاح الجلسة / النص", font=("Segoe UI", 10), bg="#EAEAEA").pack(side='right', padx=5)
        self.txt_rsa_in = ttk.Entry(f1, width=60, font=("Segoe UI", 10))
        self.txt_rsa_in.pack(side='right', padx=5)

        bf = tk.Frame(tab, bg="#EAEAEA")
        bf.pack(pady=5)
        tk.Button(bf, text="تشفير بالـ Public Key 🔒", bg="#D4AC0D", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", command=self.rsa_enc).pack(side='left', padx=10)
        tk.Button(bf, text="فك بالـ Private Key 🔓", bg="#7D6608", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", command=self.rsa_dec).pack(side='left', padx=10)

        lf2 = ttk.LabelFrame(tab, text=" [ 2 ] النتيجة ")
        lf2.pack(fill='both', expand=True, padx=10, pady=5)
        self.txt_rsa_out = scrolledtext.ScrolledText(lf2, height=8, font=("Consolas", 10))
        self.txt_rsa_out.pack(fill='both', expand=True, padx=5, pady=5)

    def rsa_enc(self):
        self.enc_rsa = self.rsa_pub.encrypt(self.txt_rsa_in.get().encode())
        self.txt_rsa_out.delete("1.0", tk.END)
        self.txt_rsa_out.insert(tk.END, self.enc_rsa.hex().upper())

    def rsa_dec(self):
        r = self.rsa_priv.decrypt(self.enc_rsa).decode()
        self.txt_rsa_out.delete("1.0", tk.END)
        self.txt_rsa_out.insert(tk.END, r)

    # --- TAB 4: HASH ---
    def ui_hash(self, tab):
        lf1 = ttk.LabelFrame(tab, text=" [ 1 ] اختيار الدالة ")
        lf1.pack(fill='x', padx=10, pady=5)
       
        f1 = tk.Frame(lf1, bg="#EAEAEA")
        f1.pack(fill='x', padx=10, pady=5)
        tk.Label(f1, text=":خوارزمية الهاش", font=("Segoe UI", 10), bg="#EAEAEA").pack(side='right', padx=5)
        self.cbo_h = ttk.Combobox(f1, values=["SHA-256", "SHA-512", "MD5", "SHA-1"], state="readonly", width=35)
        self.cbo_h.current(0)
        self.cbo_h.pack(side='right', padx=5)

        lf2 = ttk.LabelFrame(tab, text=" [ 2 ] النص المراد تجزئته ")
        lf2.pack(fill='x', padx=10, pady=5)
        self.txt_h_in = scrolledtext.ScrolledText(lf2, height=4, font=("Segoe UI", 10))
        self.txt_h_in.pack(fill='x', padx=5, pady=5)

        tk.Button(tab, text=" تنفيذ ", bg="#D4AC0D", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", command=self.run_hash).pack(pady=5)

        lf3 = ttk.LabelFrame(tab, text=" [ 3 ] قيمة الهاش (Hash Value) ")
        lf3.pack(fill='both', expand=True, padx=10, pady=5)
        self.txt_h_out = scrolledtext.ScrolledText(lf3, height=6, font=("Consolas", 10))
        self.txt_h_out.pack(fill='both', expand=True, padx=5, pady=5)

    def run_hash(self):
        t, ha = self.txt_h_in.get("1.0", tk.END).strip(), self.cbo_h.get().lower().replace('-', '')
        res = getattr(hashlib, ha)(t.encode()).hexdigest().upper()
        self.txt_h_out.delete("1.0", tk.END)
        self.txt_h_out.insert(tk.END, res.upper())

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()