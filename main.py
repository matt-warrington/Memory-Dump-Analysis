import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import subprocess

class MemoryDumpAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Memory Dump Analyzer")
        self.geometry("800x600")

        # Configure grid layout to expand
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)
        self.rowconfigure(5, weight=1)

        # GO-Global Version
        self.go_global_label = tk.Label(self, text="GO-Global Version")
        self.go_global_label.grid(column=0, row=0, padx=10, pady=5, sticky='w')
        
        self.go_global_var = tk.StringVar()
        self.go_global_combobox = ttk.Combobox(self, textvariable=self.go_global_var)
        self.go_global_combobox['values'] = [f"option {i+1}" for i in range(10)]
        self.go_global_combobox.grid(column=1, row=0, padx=10, pady=5, sticky='ew')

        # Memory Dump
        self.memory_dump_label = tk.Label(self, text="Memory Dump")
        self.memory_dump_label.grid(column=0, row=1, padx=10, pady=5, sticky='w')

        self.memory_dump_entry = tk.Entry(self, width=30)
        self.memory_dump_entry.grid(column=1, row=1, padx=10, pady=5, sticky='ew')

        self.browse_button = tk.Button(self, text="Browse...", command=self.browse_file)
        self.browse_button.grid(column=2, row=1, padx=10, pady=5, sticky='ew')

        # Dump Type
        self.dump_type_label = tk.Label(self, text="Dump Type:")
        self.dump_type_label.grid(column=0, row=2, padx=10, pady=5, sticky='w')

        self.dump_type_var = tk.StringVar(value="User")
        self.user_radio = tk.Radiobutton(self, text="User", variable=self.dump_type_var, value="User")
        self.user_radio.grid(column=1, row=2, padx=10, pady=5, sticky='w')

        self.kernel_radio = tk.Radiobutton(self, text="Kernel", variable=self.dump_type_var, value="Kernel")
        self.kernel_radio.grid(column=2, row=2, padx=10, pady=5, sticky='w')

        # App Type
        self.app_type_label = tk.Label(self, text="App Type:")
        self.app_type_label.grid(column=0, row=3, padx=10, pady=5, sticky='w')

        self.app_type_var = tk.StringVar(value="x64")
        self.x64_radio = tk.Radiobutton(self, text="x64", variable=self.app_type_var, value="x64")
        self.x64_radio.grid(column=1, row=3, padx=10, pady=5, sticky='w')

        self.x86_radio = tk.Radiobutton(self, text="x86", variable=self.app_type_var, value="x86")
        self.x86_radio.grid(column=2, row=3, padx=10, pady=5, sticky='w')

        # Analyze Button
        self.analyze_button = tk.Button(self, text="Analyze", command=self.analyze)
        self.analyze_button.grid(column=1, row=4, padx=10, pady=10, sticky='ew')

        # Output Text Box (Scrollable)
        self.output_text = scrolledtext.ScrolledText(self, width=45, height=10)
        self.output_text.grid(column=0, row=5, columnspan=3, padx=10, pady=10, sticky='nsew')

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Dump Files", "*.DMP"), ("All Files", "*.*")])
        if file_path:
            self.memory_dump_entry.delete(0, tk.END)
            self.memory_dump_entry.insert(0, file_path)

    def analyze(self):
        gg_version = self.go_global_var.get()
        dump_type = self.dump_type_var.get()
        app_type = self.app_type_var.get()
        memory_dump_path = self.memory_dump_entry.get()

        if not gg_version or not dump_type or not app_type or not memory_dump_path:
            self.output_text.insert(tk.END, "Please fill all fields.\n")
            return

        command = f'DumpChk -y {gg_version}_{dump_type}_{app_type} "{memory_dump_path}"'
        self.output_text.insert(tk.END, f"Running command: {command}\n")

        try:
            output = subprocess.check_output(
                command,
                shell=True,
                text=True,
                cwd="C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Windows Kits\\Debugging Tools for Windows (X64)"
            )
            self.output_text.insert(tk.END, output)
        except subprocess.CalledProcessError as e:
            self.output_text.insert(tk.END, f"An error occurred:\n{e.output}\n")

if __name__ == "__main__":
    app = MemoryDumpAnalyzerApp()
    app.mainloop()
