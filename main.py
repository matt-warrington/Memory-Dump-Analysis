import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import subprocess
import GOGlobal
import os
import myUtils

DEFAULT_SYMBOL_BASE_PATH = "C:\\Users\\Matt\\Documents\\Tools\\Symbols" # "C:\\Symbols"  <-- for fileservercolo. 

class MemoryDumpAnalyzerApp(tk.Tk):
    """
    MemoryDumpAnalyzerApp class for analyzing memory dumps with specified parameters.

    Methods:
    - __init__: Initializes the MemoryDumpAnalyzerApp class and sets up the GUI layout.
    - createWidgets: Creates all the necessary widgets for the GUI.
    - run_command: Executes a WinDbg command entered in the GUI.
    - browse_file: Opens a file dialog for browsing memory dump files.
    - get_symbol_path: Generates the symbol path based on selected parameters.
    - analyze: Analyzes the memory dump using specified parameters and displays the output.

    Raises:
    - subprocess.CalledProcessError: If an error occurs during the subprocess execution.

    Returns:
    - None
    """
    def __init__(self):
        super().__init__()

        self.title("Memory Dump Analyzer")
        self.geometry("1200x800")

        # Configure grid layout to expand
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)
        self.rowconfigure(5, weight=1)

        self.createWidgets()

    def createWidgets(self):
        # Memory Dump
        self.memory_dump_label = tk.Label(self, text="Memory Dump")
        self.memory_dump_label.grid(column=0, row=0, padx=10, pady=5, sticky='w')

        self.memory_dump_entry = tk.Entry(self, width=30)
        self.memory_dump_entry.grid(column=1, row=0, padx=10, pady=5, sticky='ew')

        self.browse_button = tk.Button(self, text="Browse...", command=self.browse_file)
        self.browse_button.grid(column=2, row=0, padx=10, pady=5, sticky='ew')
        
        # GO-Global Version
        self.go_global_label = tk.Label(self, text="GO-Global Version")
        self.go_global_label.grid(column=0, row=1, padx=10, pady=5, sticky='w')
        
        self.go_global_var = tk.StringVar()
        self.go_global_combobox = ttk.Combobox(self, textvariable=self.go_global_var)
        self.go_global_combobox['values'] = GOGlobal.versions
        self.go_global_combobox.grid(column=1, row=1, padx=10, pady=5, sticky='ew')

        # Dump Type
        self.radio_buttons_frame = tk.Frame(self)
        self.radio_buttons_frame.grid(column=0, row=2, columnspan=3, padx=5, pady=10)

        self.dump_type_label = tk.Label(self.radio_buttons_frame, text="Dump Type:")
        self.dump_type_label.grid(column=0, row=0, padx=10, pady=5, sticky='w')

        self.dump_type_var = tk.StringVar(value="User")
        self.user_radio = tk.Radiobutton(self.radio_buttons_frame, text="User", variable=self.dump_type_var, value="User")
        self.user_radio.grid(column=1, row=0, padx=10, pady=5, sticky='w')

        self.kernel_radio = tk.Radiobutton(self.radio_buttons_frame, text="Kernel", variable=self.dump_type_var, value="Kernel")
        self.kernel_radio.grid(column=2, row=0, padx=10, pady=5, sticky='w')

        # App Type
        self.app_type_label = tk.Label(self.radio_buttons_frame, text="App Type:")
        self.app_type_label.grid(column=0, row=1, padx=10, pady=5, sticky='w')

        self.app_type_var = tk.StringVar(value="64-bit")
        self.x64_radio = tk.Radiobutton(self.radio_buttons_frame, text="64-bit", variable=self.app_type_var, value="64-bit")
        self.x64_radio.grid(column=1, row=1, padx=10, pady=5, sticky='w')

        self.x86_radio = tk.Radiobutton(self.radio_buttons_frame, text="32-bit", variable=self.app_type_var, value="32-bit")
        self.x86_radio.grid(column=2, row=1, padx=10, pady=5, sticky='w')

        # App Location
        self.app_location_label = tk.Label(self.radio_buttons_frame, text="Location:")
        self.app_location_label.grid(column=0, row=2, padx=10, pady=5, sticky='w')

        self.app_location_var = tk.StringVar(value="Client")
        self.client_radio = tk.Radiobutton(self.radio_buttons_frame, text="Client", variable=self.app_location_var, value="Client")
        self.client_radio.grid(column=1, row=2, padx=10, pady=5, sticky='w')

        self.server_radio = tk.Radiobutton(self.radio_buttons_frame, text="Server", variable=self.app_location_var, value="Server")
        self.server_radio.grid(column=2, row=2, padx=10, pady=5, sticky='w')

        # Analyze Button
        self.analyze_button = tk.Button(self, text="Analyze", command=self.analyze)
        self.analyze_button.grid(column=1, row=3, padx=10, pady=10, sticky='ew')

        # Output Text Box (Scrollable)
        self.output_text = scrolledtext.ScrolledText(self, width=45, height=10)
        self.output_text.grid(column=0, row=4, columnspan=3, rowspan=2, padx=10, pady=10, sticky='nsew')

        # Add the ability to make WinDbg commands - 06/26/24, not sure if this is possible at the moment. 
        self.command_frame = tk.Frame(self)
        self.command_frame.grid(column=1, row=6, padx=10, sticky='ew')
        self.command_label = tk.Label(self.command_frame, text="Enter winDbg command:")
        self.command_label.pack(padx=5, pady=10)
        self.command_var = tk.StringVar()
        self.command_entry = tk.Entry(self.command_frame, width=100, textvariable=self.command_var)
        self.command_entry.pack(padx=5, pady=10, fill=tk.X, expand=True)
        self.command_button = tk.Button(self.command_frame, width=20, text="Enter", command=self.run_command)
        self.command_button.pack(padx=5, pady=10)
    
    
    def run_command(self):
        # this might not be necessary because DumpChk might not actually be able to do anything else but check the dump initially.
        command = self.command_entry.get()
        try:
            output = subprocess.check_output(
                command,
                shell=True,
                text=True,
                cwd="C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64"
            )
            self.output_text.insert(tk.END, output)
        except subprocess.CalledProcessError as e:
            self.output_text.insert(tk.END, f"An error occurred:\n{e.output}\n")
    
    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Dump Files", "*.DMP"), ("All Files", "*.*")])
        if file_path:
            self.memory_dump_entry.delete(0, tk.END)
            self.memory_dump_entry.insert(0, file_path)
            
    def get_symbol_path(self):
        gg_version = self.go_global_var.get()
        dump_type = self.dump_type_var.get()
        dump_type_path = "AttestationSigning_DisplayAudioDriver\\DisplayDriver" if dump_type == "Kernel" else ""

        app_type = self.app_type_var.get()
        app_type_path = "devKit-x64Release" if app_type == "64-bit" else "devKit-Win32Release"

        app_location_path = self.app_location_var.get().lower()

        symbol_path = f"{DEFAULT_SYMBOL_BASE_PATH}\\{gg_version}\\"
        if len(dump_type_path) > 0:
            symbol_path += dump_type_path
        else:
            symbol_path += f"{app_type_path}\\Release\\{app_location_path}"

        if os.path.exists(symbol_path):
            return symbol_path
        else:
            print(f"WARNING: No symbols found at {symbol_path}. Copy symbols from \\\\qnapnas.graphon.com\\Builds to C:\\Symbols and try again. ")
            return "" 

    def analyze(self):
        """
        Analyzes the memory dump using the specified parameters and displays the output in the output text box.

        Raises:
            subprocess.CalledProcessError: If an error occurs during the subprocess execution.

        Returns:
            None
        """
        gg_version = self.go_global_var.get()
        dump_type = self.dump_type_var.get()
        app_type = self.app_type_var.get()
        memory_dump_path = self.memory_dump_entry.get()

        if not gg_version or not dump_type or not app_type or not memory_dump_path:
            self.output_text.insert(tk.END, "Please fill all fields.\n")
            return

        command = f'WinDbg -z {memory_dump_path} -y srv*;{self.get_symbol_path()} -c "!analyze -v"'
        self.output_text.insert(tk.END, f"Running command: {command}\n")

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                text=True,
                cwd="C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            for line in process.stdout:
                self.output_text.insert(tk.END, line)
            for line in process.stderr:
                self.output_text.insert(tk.END, line)

            process.wait()
        except subprocess.CalledProcessError as e:
            self.output_text.insert(tk.END, f"An error occurred:\n{e.output}\n")

if __name__ == "__main__":
    app = MemoryDumpAnalyzerApp()
    app.mainloop()
