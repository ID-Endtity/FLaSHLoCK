import tkinter as tk
from tkinter import Checkbutton, messagebox
import backend

import backend


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Password check")
        root.geometry("380x240")
        root.resizable(False, False)
        folder=backend.app_dir()
        
        tk.Label(root, text=f"Folder: {folder}",
                    wraplength=360, justify="left").pack(pady=10)
        self.pwd= ""
        self.folder = backend.app_dir()
        self.root.geometry("500x300")
        self.menu()

    def menu(self):
        tk.Label(self.root, text=f"Working in directory: {self.folder}", justify="center").pack(pady=10) #, wraplength=400
        tk.Button(self.root, text="🔒 Encrypt", width=24, command=self.encr).pack(pady=5)
        tk.Button(self.root, text="🔓 Decrypt", width=24, command=lambda: self.check(type=2)).pack(pady=5)
        tk.Button(self.root, text="Exit", width=24, command=self.root.destroy).pack(pady=5)

    def encr(self):
        if self.pwd == "":
            self.set_pwd()
            return 
        else:
            self.check(type=1)

    def set_pwd(self):
        self.win_set_pwd = tk.Toplevel(self.root)
        self.win_set_pwd.title("Set Password")

        tk.Label(self.win_set_pwd, text="Enter your password:").pack(pady=5)

        #PASSWORD1
        self.psw1=tk.StringVar()
        self.input1=tk.Entry(self.win_set_pwd, textvariable=self.psw1,width=40, show="*")
        self.input1.pack(pady=0,padx=20,anchor="w")
        #CHECKBOX1
        self.chk1=tk.IntVar()
        self.chbox1=Checkbutton(self.win_set_pwd, text="Show password",variable=self.chk1, onvalue=1, offvalue=0, 
    command=lambda: self.show_password(self.chk1, self.input1))
        self.chbox1.pack(pady=0, padx=20, anchor="w")

        tk.Label(self.win_set_pwd, text="Confirm your password:").pack(pady=5)

        #PASSWORD2
        self.psw2=tk.StringVar()
        self.input2=tk.Entry(self.win_set_pwd, textvariable=self.psw2,width=40, show="*")
        self.input2.pack(pady=0,padx=20,anchor="w")
        #CHECKBOX2
        self.chk2=tk.IntVar()
        self.chbox2=Checkbutton(self.win_set_pwd, text="Show password",variable=self.chk2, onvalue=1, offvalue=0, 
    command=lambda: self.show_password(self.chk2, self.input2))
        self.chbox2.pack(pady=0, padx=20, anchor="w")

        #BUTTON
        tk.Button(self.win_set_pwd, text="Submit", width=24, command=lambda: self.chk_pwd(self.psw1.get(), self.psw2.get(), type=0)).pack(pady=10)


    def show_password(self, checker, entry):
        entry.config(show="" if checker.get() else "*")


    def check(self, type): #type 1 for encryption, type 2 for decryption
        if self.pwd == "" and type:
            messagebox.showerror("Error", "Password not set. Please set a password first and encrypt your data.")
            return 
        self.win_check = tk.Toplevel(self.root)
        self.win_check.title("Check Password")

        tk.Label(self.win_check, text="Enter your password:").pack(pady=5)

        self.psw=tk.StringVar()
        self.input=tk.Entry(self.win_check, textvariable=self.psw,width=40, show="*")
        self.input.pack(pady=0,padx=20,anchor="w")

        self.chk=tk.IntVar()
        self.chbox=Checkbutton(self.win_check, text="Show password",variable=self.chk, onvalue=1, offvalue=0, 
    command=lambda: self.show_password(self.chk, self.input))
        self.chbox.pack(pady=0, padx=20, anchor="w")

        tk.Button(self.win_check, text="Submit", width=24, command=lambda: self.chk_pwd(self.pwd, self.psw.get(), type=type)).pack(pady=10)


    def chk_pwd(self, pwd1, pwd2, type):
        if len(pwd1) < 8 and not type:
            messagebox.showwarning("Weak password", "Use at least 8 characters.")

        elif pwd1 == pwd2 and not type:
            messagebox.showinfo("Success", "Passwords match. Started encryption.")
            self.pwd = pwd1
            self.win_set_pwd.destroy()
            result = backend.encrypt(pwd1)
            messagebox.showinfo("Done", result)
            #Encryption can proceed now

        elif pwd1 == pwd2:
            self.win_check.destroy()
            result = backend.encrypt(pwd1) if type == 1 else backend.decrypt(pwd1) #Encryption or decryption can proceed now
            messagebox.showinfo("Done", result)
        
        elif pwd1 != pwd2 and type:
            messagebox.showerror("Error", "Wrong password.")
        else:
            messagebox.showerror("Error", "Passwords don't match.")
        return 




def main():
    root = tk.Tk()
    App(root)
    root.mainloop()




if __name__ == "__main__":
    main()




