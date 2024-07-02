import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import GOGlobal
import os
import myUtils
import psutil
import tempfile
import zipfile

CONFIG_FILE_PATH = "config.json"
DEFAULT_WINDBG_PATH = "C:/Program Files (x86)/Windows Kits/10/Debuggers/x86"

class MemoryDumpAnalyzerApp(tk.Tk):
    """
    MemoryDumpAnalyzerApp class for analyzing memory dumps with specified parameters.

    Methods:
    - __init__: Initializes the MemoryDumpAnalyzerApp class and sets up the GUI layout.
    - createWidgets: Creates all the necessary widgets for the GUI.
    - browse_file: Opens a file dialog for browsing memory dump files.
    - get_symbol_path: Generates the symbol path based on selected parameters.
    - launch_winDbg: Opens the memory dump in WinDbg using specified parameters.

    Raises:
    - subprocess.CalledProcessError: If an error occurs during the subprocess execution.

    Returns:
    - None
    """
    def __init__(self):
        super().__init__()

        # Have the user set base paths based on their machine. They can set these once the first time they run the program, and change it from config.json after that. 
        self.symbol_base_path = self.get_symbol_base_path()
        self.dump_base_path = self.get_dump_base_path()
        self.winDbg_path = self.get_winDbg_path()

        self.title("Memory Dump Analyzer")

        # Configure grid layout to expand
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)
        self.rowconfigure(5, weight=1)

        self.createWidgets()

        # Bind the close event to the on_closing method
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        self.destroy()

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
        self.go_global_combobox['values'] = self.get_go_global_versions()
        self.go_global_combobox.grid(column=1, row=1, padx=10, pady=5, sticky='ew')

        # Dump Type
        self.radio_buttons_frame = tk.Frame(self)
        self.radio_buttons_frame.grid(column=0, row=2, columnspan=3, padx=5, pady=10)

        self.dump_type_label = tk.Label(self.radio_buttons_frame, text="Dump Type:")
        self.dump_type_label.grid(column=0, row=0, padx=10, pady=5, sticky='w')

        self.dump_type_var = tk.StringVar(value="User")
        self.user_radio = tk.Radiobutton(self.radio_buttons_frame, text="User", variable=self.dump_type_var, value="User", command=self.update_visibility)
        self.user_radio.grid(column=1, row=0, padx=10, pady=5, sticky='w')

        self.kernel_radio = tk.Radiobutton(self.radio_buttons_frame, text="Kernel", variable=self.dump_type_var, value="Kernel", command=self.update_visibility)
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

        # Launch WinDbg Button
        self.launch_winDbg_button = tk.Button(self, text="Launch WinDbg", command=self.launch_winDbg)
        self.launch_winDbg_button.grid(column=1, row=3, padx=10, pady=10, sticky='ew')

        self.update_visibility()

    def get_winDbg_path(self):
        def check_windbg_path(path):
            return os.path.exists(os.path.join(path, "windbg.exe"))

        default_windbg_path = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64"

        if check_windbg_path(default_windbg_path):
            if not os.path.exists(CONFIG_FILE_PATH):
                config = {"windbg_path": default_windbg_path}
                with open(CONFIG_FILE_PATH, 'w') as config_file:
                    json.dump(config, config_file)
            else:
                # Read the WinDbg path from the config file
                with open(CONFIG_FILE_PATH, 'r') as config_file:
                    config = json.load(config_file)

                config["windbg_path"] = default_windbg_path
                with open(CONFIG_FILE_PATH, 'w') as config_file:
                    json.dump(config, config_file)

            return default_windbg_path

        if not os.path.exists(CONFIG_FILE_PATH):
            # First run, set the default WinDbg path
            new_base_path = myUtils.select_dir("Select the path for WinDbg...")
            if not check_windbg_path(new_base_path):
                messagebox.showerror("WinDbg Not Found", "WinDbg.exe could not be found at the specified location. Please ensure WinDbg is installed and include the correct path in the config file.")
                return ""
            config = {"windbg_path": new_base_path}
            with open(CONFIG_FILE_PATH, 'w') as config_file:
                json.dump(config, config_file)
            return new_base_path
        else:
            # Read the WinDbg path from the config file
            with open(CONFIG_FILE_PATH, 'r') as config_file:
                config = json.load(config_file)

            base_path = config.get("windbg_path", "")
            if base_path == "" or not check_windbg_path(base_path):
                new_base_path = myUtils.select_dir("Select the path for WinDbg...")
                if not check_windbg_path(new_base_path):
                    messagebox.showerror("WinDbg Not Found", "WinDbg.exe could not be found at the specified location. Please ensure WinDbg is installed and include the correct path in the config file.")
                    return ""
                config["windbg_path"] = new_base_path
                with open(CONFIG_FILE_PATH, 'w') as config_file:
                    json.dump(config, config_file)
                return new_base_path

            return base_path
    
    def update_visibility(self):
        if self.dump_type_var.get() == "Kernel":
            self.app_type_label.grid_remove()
            self.x64_radio.grid_remove()
            self.x86_radio.grid_remove()
            self.app_location_label.grid_remove()
            self.client_radio.grid_remove()
            self.server_radio.grid_remove()
        else:
            self.app_type_label.grid()
            self.x64_radio.grid()
            self.x86_radio.grid()
            self.app_location_label.grid()
            self.client_radio.grid()
            self.server_radio.grid()
    
    def get_go_global_versions(self):
        if os.path.exists(self.symbol_base_path):
            return [d for d in os.listdir(self.symbol_base_path) if os.path.isdir(os.path.join(self.symbol_base_path, d))]
        else:
            return GOGlobal.versions

    def browse_file(self):
        file_path = myUtils.select_file("DMP", "*.dmp", self.dump_base_path)
        if file_path:
            self.memory_dump_entry.delete(0, tk.END)
            self.memory_dump_entry.insert(0, file_path)

    def get_symbol_base_path(self):
        if not os.path.exists(CONFIG_FILE_PATH):
            # First run, set the default symbol path
            new_base_path = myUtils.select_dir("Select a base path for finding symbols...")
            config = {"symbol_base_path": new_base_path}
            with open(CONFIG_FILE_PATH, 'w') as config_file:
                json.dump(config, config_file)
            return new_base_path
        else:
            # Read the symbol path from the config file
            with open(CONFIG_FILE_PATH, 'r') as config_file:
                config = json.load(config_file)

            base_path = config.get("symbol_base_path", "")
            if base_path == "" or not os.path.exists(base_path):
                base_path = myUtils.select_dir("Select a base path for finding symbols...")
                config["symbol_base_path"] = base_path
                with open(CONFIG_FILE_PATH, 'w') as config_file:
                    json.dump(config, config_file)
            
            return base_path

    def get_dump_base_path(self):
        if not os.path.exists(CONFIG_FILE_PATH):
            # First run, set the default dump path
            new_base_path = myUtils.select_dir("Select a base path for finding dumps...")
            config = {"dump_base_path": new_base_path}
            with open(CONFIG_FILE_PATH, 'w') as config_file:
                json.dump(config, config_file)
            return new_base_path
        else:
            # Read the dump path from the config file
            with open(CONFIG_FILE_PATH, 'r') as config_file:
                config = json.load(config_file)

            base_path = config.get("dump_base_path", "")
            if base_path == "" or not os.path.exists(base_path):
                base_path = myUtils.select_dir("Select a base path for finding dumps...")
                config["dump_base_path"] = base_path
                with open(CONFIG_FILE_PATH, 'w') as config_file:
                    json.dump(config, config_file)
            
            return base_path


    def get_symbol_path(self):
        gg_version = self.go_global_var.get()
        dump_type = self.dump_type_var.get()
        dump_type_path = "AttestationSigning_DisplayAudioDriver/DisplayDriver" if dump_type == "Kernel" else ""

        app_type = self.app_type_var.get()
        app_type_path = "devKit-x64Release" if app_type == "64-bit" else "devKit-Win32Release"

        app_location_path = self.app_location_var.get().lower()

        symbol_path = f"{self.symbol_base_path}/{gg_version}/"
        if len(dump_type_path) > 0:
            symbol_path += dump_type_path
        else:
            symbol_path += f"{app_type_path}/Release/{app_location_path}"

        # Check if the path is a .zip file and unzip it if necessary
        if symbol_path.endswith('.zip') and os.path.isfile(symbol_path):
            with zipfile.ZipFile(symbol_path, 'r') as zip_ref:
                temp_dir = tempfile.mkdtemp()
                zip_ref.extractall(temp_dir)
                symbol_path = temp_dir

        if not os.path.exists(symbol_path):
            messagebox.showwarning("Path Not Found", f"No symbols found at {symbol_path}. \n\nPlease find the symbols you are looking for and upload the path here.")
            new_symbol_path = filedialog.askdirectory(title="Select Path of Symbols")
            if new_symbol_path:
                return new_symbol_path
            else:
                messagebox.showinfo("Proceeding Without Symbols", "No new path selected. Proceeding without additional symbols.")
                return ""
            
        return symbol_path
    
    def launch_winDbg(self):
        """
        Opens the memory dump in WinDbg using the specified parameters.

        Raises:
            subprocess.CalledProcessError: If an error occurs during the subprocess execution.

        Returns:
            None
        """
        #gg_version = self.go_global_var.get()
        #dump_type = self.dump_type_var.get()
        #app_type = self.app_type_var.get()
        memory_dump_path = self.memory_dump_entry.get()

        # All other fields are implemented 
        if not memory_dump_path or not self.go_global_var.get():
            messagebox.showwarning("Input Error", "Please fill all fields.")
            return

        # Check for running instances of WinDbg
        winDbg_count = sum(1 for proc in psutil.process_iter(['name']) if proc.info['name'] == 'windbg.exe')
        max_instances = 5  # Set your threshold here

        if winDbg_count >= max_instances:
            messagebox.showwarning("Instance Limit Reached", f"Too many instances of WinDbg are running ({winDbg_count}). Please close some instances before launching a new one.")
            return

        command = f'WinDbg -z {memory_dump_path} -y srv*;{self.get_symbol_path()} -c "!analyze -v"'
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                text=False,
                cwd=self.winDbg_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Execution Error", f"An error occurred:\n{e.output}")

if __name__ == "__main__":
    app = MemoryDumpAnalyzerApp()
    app.mainloop()
