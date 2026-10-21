import tkinter as tk
from tkinter import Checkbutton, messagebox

import backend


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Password check")
        self.folder = backend.app_dir()
        self.root.geometry("500x300")
        self.root.resizable(False, False)
        self.menu()

    def menu(self):
        tk.Label(self.root, text=f"Working in directory: {self.folder}", justify="center").pack(pady=10)
        tk.Button(self.root, text="🔒 Encrypt", width=24, command=self.encr).pack(pady=5)
        tk.Button(self.root, text="🔓 Decrypt", width=24, command=lambda: self.check(type=2)).pack(pady=5)
        # ===== RESET PASSWORD — закомментируй эту строку, чтобы отключить кнопку =====
        tk.Button(self.root, text="🔑 Reset Password", width=24, command=self.reset_pwd).pack(pady=5)
        # ==================================================================================
        tk.Button(self.root, text="Exit", width=24, command=self.root.destroy).pack(pady=5)

    def encr(self):
        # Пароль уже задан (маркер существует) → проверить и зашифровать.
        # Иначе — это первый запуск → установить пароль.
        if backend.has_marker():
            self.check(type=1)
        else:
            self.set_pwd()

    def set_pwd(self):
        self.win_set_pwd = tk.Toplevel(self.root)
        self.win_set_pwd.title("Set Password")

        tk.Label(self.win_set_pwd, text="Enter your password:").pack(pady=5)

        # PASSWORD 1
        self.psw1 = tk.StringVar()
        self.input1 = tk.Entry(self.win_set_pwd, textvariable=self.psw1, width=40, show="*")
        self.input1.pack(pady=0, padx=20, anchor="w")
        self.chk1 = tk.IntVar()
        self.chbox1 = Checkbutton(self.win_set_pwd, text="Show password", variable=self.chk1, onvalue=1, offvalue=0,
                                  command=lambda: self.show_password(self.chk1, self.input1))
        self.chbox1.pack(pady=0, padx=20, anchor="w")

        tk.Label(self.win_set_pwd, text="Confirm your password:").pack(pady=5)

        # PASSWORD 2
        self.psw2 = tk.StringVar()
        self.input2 = tk.Entry(self.win_set_pwd, textvariable=self.psw2, width=40, show="*")
        self.input2.pack(pady=0, padx=20, anchor="w")
        self.chk2 = tk.IntVar()
        self.chbox2 = Checkbutton(self.win_set_pwd, text="Show password", variable=self.chk2, onvalue=1, offvalue=0,
                                  command=lambda: self.show_password(self.chk2, self.input2))
        self.chbox2.pack(pady=0, padx=20, anchor="w")

        # SUBMIT
        tk.Button(self.win_set_pwd, text="Submit", width=24,
                  command=lambda: self.submit_set_pwd(self.psw1.get(), self.psw2.get())).pack(pady=10)

    def show_password(self, checker, entry):
        entry.config(show="" if checker.get() else "*")

    def check(self, type):  # type 1 = шифрование, type 2 = расшифровка
        if not backend.has_marker():
            messagebox.showerror("Error", "No password set yet. Click Encrypt first.")
            return
        
        self.win_check = tk.Toplevel(self.root)
        self.win_check.title("Check Password")

        tk.Label(self.win_check, text="Enter your password:").pack(pady=5)

        self.psw = tk.StringVar()
        self.input = tk.Entry(self.win_check, textvariable=self.psw, width=40, show="*")
        self.input.pack(pady=0, padx=20, anchor="w")

        self.chk = tk.IntVar()
        self.chbox = Checkbutton(self.win_check, text="Show password", variable=self.chk, onvalue=1, offvalue=0,
                                 command=lambda: self.show_password(self.chk, self.input))
        self.chbox.pack(pady=0, padx=20, anchor="w")

        # SUBMIT
        tk.Button(self.win_check, text="Submit", width=24,
                  command=lambda: self.verify_pwd(self.psw.get(), type)).pack(pady=10)

    def submit_set_pwd(self, pwd1, pwd2):
        """Первый запуск: сравнивает два ввода пароля, затем шифрует."""
        if len(pwd1) < 8:
            messagebox.showwarning("Weak password", "Use at least 8 characters.")
        elif pwd1 == pwd2:
            self.win_set_pwd.destroy()
            result = backend.encrypt(pwd1)
            messagebox.showinfo("Done", result)
        else:
            messagebox.showerror("Error", "Passwords don't match.")

    def verify_pwd(self, entered, type):
        """Проверяет введённый пароль через маркер, затем шифрует или расшифровывает."""
        self.win_check.destroy()
        result = backend.encrypt(entered) if type == 1 else backend.decrypt(entered)
        messagebox.showinfo("Done", result)

    # ==================== RESET PASSWORD (закомментируй, чтобы отключить) ====================
    def reset_pwd(self):
        if not backend.has_marker():
            messagebox.showerror("Error", "No password set yet.")
            return
        result = backend.reset_password()
        messagebox.showinfo("Done", result)
    # ==========================================================================================


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
