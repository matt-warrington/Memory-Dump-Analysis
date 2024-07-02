import json
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import GOGlobal
import os
import myUtils
import psutil
import tempfile
import zipfile
import zlib
import bz2
import lzma

CONFIG_FILE_PATH = "config.json"
DEFAULT_WINDBG_PATH = "C:/Program Files (x86)/Windows Kits/10/Debuggers/x86"

class MemoryDumpAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.symbol_base_path = self.get_symbol_base_path()
        self.dump_base_path = self.get_dump_base_path()
        self.winDbg_path = self.get_winDbg_path()
        self.shared_folder_path = self.get_backup_dump_path()

        self.title("Memory Dump Analyzer")

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)
        self.rowconfigure(5, weight=1)

        self.dmp_files = []
        self.dump_settings = []

        self.createWidgets()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        self.destroy()

    def createWidgets(self):
        self.case_number_label = tk.Label(self, text="Case Number: ")
        self.case_number_label.grid(column=0, row=0, padx=10, pady=5, sticky='w')
        self.case_number_entry = tk.Entry(self, width=50)
        self.case_number_entry.grid(column=1, row=0, padx=10, pady=5, sticky='w')
        self.find_dump_button = tk.Button(self, text="Find Dump", command=self.find_dmp_files)
        self.find_dump_button.grid(column=2, row=0, padx=10, pady=5, sticky='w')
        
        # Memory Dump
        self.memory_dump_label = tk.Label(self, text="Add individual memory dump: ")
        self.memory_dump_label.grid(column=0, row=1, padx=10, pady=5, sticky='w')

        self.memory_dump_entry = tk.Entry(self, width=30)
        self.memory_dump_entry.grid(column=1, row=1, padx=10, pady=5, sticky='ew')

        self.browse_button = tk.Button(self, text="Browse...", command=self.browse_file)
        self.browse_button.grid(column=2, row=1, padx=10, pady=5, sticky='ew')
        
        # GO-Global Version
        self.go_global_label = tk.Label(self, text="GO-Global Version")
        self.go_global_label.grid(column=0, row=2, padx=10, pady=5, sticky='w')
        
        self.go_global_var = tk.StringVar()
        self.go_global_combobox = ttk.Combobox(self, textvariable=self.go_global_var)
        self.go_global_combobox['values'] = self.get_go_global_versions()
        self.go_global_combobox.grid(column=1, row=2, padx=10, pady=5, sticky='ew')

        # Create a frame for the table
        self.table_frame = ttk.Frame(self)
        self.table_frame.grid(column=0, row=3, columnspan=3, padx=10, pady=10, sticky='nsew')

        # Create the table
        self.table = ttk.Treeview(self.table_frame, columns=('File', 'Dump Type', 'App Type', 'App Location'), show='headings')
        self.table.heading('File', text='File')
        self.table.heading('Dump Type', text='Dump Type')
        self.table.heading('App Type', text='App Type')
        self.table.heading('App Location', text='App Location')
        self.table.pack(expand=True, fill='both')
        self.table.bind('<Double-1>', self.on_cell_double_click)
        # Hide the table initially
        self.table_frame.grid_remove()

        # Launch WinDbg Button
        self.launch_winDbg_button = tk.Button(self, text="Launch WinDbg", command=self.launch_winDbg)
        self.launch_winDbg_button.grid(column=1, row=4, padx=10, pady=10, sticky='ew')

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
    

    def find_dmp_files(self):
        case_number = self.case_number_entry.get()
        if not case_number or case_number == "":
            case_selected = myUtils.select_dir(initialDir=self.dump_base_path)
            case_number = os.path.basename(case_selected)

        primary_path = os.path.join(self.dump_base_path, case_number)
        secondary_path = os.path.join(self.shared_folder_path, case_number)

        self.dmp_files = []  # Clear any previously found files

        # Helper function to search for .dmp files recursively
        def search_for_dmp_files(base_path):
            dmp_files = []
            for root, dirs, files in os.walk(base_path):
                # Only search directories with "dump" or "dmp" in the name
                dirs[:] = [d for d in dirs if 'dump' in d.lower() or 'dmp' in d.lower()]
                for file in files:
                    if file.lower().endswith('.dmp'):
                        dmp_files.append(os.path.join(root, file))
            return dmp_files

        # Helper function to unzip files
        def unzip_files(zip_path, extract_to):
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    for file_info in zip_ref.infolist():
                        try:
                            # First, try to extract using zipfile's built-in extract method
                            zip_ref.extract(file_info, extract_to)
                        except:# zipfile.error:
                            # If that fails, try manual decompression
                            try:
                                data = None
                                if file_info.compress_type == zipfile.ZIP_STORED:
                                    data = zip_ref.read(file_info.filename)
                                elif file_info.compress_type == zipfile.ZIP_DEFLATED:
                                    data = zlib.decompress(zip_ref.read(file_info.filename), -15)
                                elif file_info.compress_type == zipfile.ZIP_BZIP2:
                                    data = bz2.decompress(zip_ref.read(file_info.filename))
                                elif file_info.compress_type == zipfile.ZIP_LZMA:
                                    data = lzma.decompress(zip_ref.read(file_info.filename))
                                elif file_info.compress_type == 9:  # Custom handling for compression type 9
                                    # Attempt extraction using 7z for unsupported compression methods
                                    subprocess.run(['7z', 'x', '-o' + extract_to, zip_path], check=True)
                                else:
                                    raise NotImplementedError(f"Unsupported compression method: {file_info.compress_type}")
                                
                                if data is not None:
                                    target_path = os.path.join(extract_to, file_info.filename)
                                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                                    with open(target_path, 'wb') as f:
                                        f.write(data)
                            except Exception as e:
                                # If all methods fail, inform the user but continue with other files
                                messagebox.showwarning("Extraction Warning", 
                                                    f"Could not extract file '{file_info.filename}' from '{os.path.basename(zip_path)}'.\n"
                                                    "The file may be corrupted or use an unsupported compression method.\n"
                                                    f"Compression type: {file_info.compress_type}")
                
                #print(f"Extraction of {zip_path} completed.")
            except zipfile.BadZipFile:
                file_name = os.path.basename(zip_path)
                messagebox.showerror("Invalid Zip File", 
                                    f"The file '{file_name}' is not a valid zip file or is corrupted.")
            except Exception as e:
                file_name = os.path.basename(zip_path)
                messagebox.showerror("Error", f"An error occurred while extracting '{file_name}': {str(e)}")
        
        def process_directory(path):
            dmp_files = search_for_dmp_files(path)
            # If no .dmp files found, look for zip files to extract
            if not dmp_files:
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.lower().endswith('.zip'):
                            zip_path = os.path.join(root, file)
                            extract_to = os.path.join(root, os.path.splitext(file)[0])
                            unzip_files(zip_path, extract_to)
                            # Search for .dmp files in the extracted folder
                            extracted_dmp_files = search_for_dmp_files(extract_to)
                            if extracted_dmp_files:
                                dmp_files.extend(extracted_dmp_files)
            return dmp_files

        # Check primary location
        if os.path.isdir(primary_path):
            dmp_files = process_directory(primary_path)
        elif os.path.isdir(secondary_path):
            temp_dir = os.path.join(self.dump_base_path, case_number)
            shutil.copytree(secondary_path, temp_dir)
            dmp_files = process_directory(temp_dir)
        else:
            messagebox.showerror("Error", f"No directory found for case {case_number} in either location.\n\n{primary_path}\n{secondary_path}")

        if dmp_files:
            self.dmp_files = dmp_files
            self.memory_dump_entry.delete(0, tk.END)
            self.memory_dump_entry.insert(0, ', '.join(self.dmp_files))
            self.populate_table()
            return
        else:
            messagebox.showerror("Error", f"No dump files found for case {case_number} in either location.\n\n{primary_path}\n{secondary_path}")
    
    
    def populate_table(self):
        # Clear existing items
        for item in self.table.get_children():
            self.table.delete(item)

        # Populate the table with dump files and default settings
        for dmp_file in self.dmp_files:
            if os.path.basename(dmp_file) == 'MEMORY.DMP':
                item_id = self.table.insert('', 'end', values=(os.path.basename(dmp_file), 'Kernel', '-', '-'))
            else:
                item_id = self.table.insert('', 'end', values=(os.path.basename(dmp_file), 'User', '64-bit', 'Server'))
            self.setup_item_dropdowns(item_id)

        # Show the table
        self.table_frame.grid()

    def setup_item_dropdowns(self, item_id):
        dump_types = ['User', 'Kernel']
        app_types = ['64-bit', '32-bit', '-']
        app_locations = ['Client', 'Server', '-']

        for col, values in [('Dump Type', dump_types), ('App Type', app_types), ('App Location', app_locations)]:
            current_value = self.table.set(item_id, col)
            combo = ttk.Combobox(self.table, values=values, state='readonly')
            combo.set(current_value)
            combo.bind('<<ComboboxSelected>>', lambda e, item=item_id, column=col: self.on_combo_select(e, item, column))
            
            # Configure the treeview column to use the combobox
            self.table.column(col, anchor='center', width=100)
            self.table.set(item_id, col, current_value)


    def on_combo_select(self, event, item, column):
        selected_value = event.widget.get()
        self.table.set(item, column, selected_value)

        # Check if the selected value for 'Dump Type' is 'Kernel'
        if column == '#2' and selected_value == 'Kernel':  # '#2' corresponds to 'Dump Type'
            self.table.set(item, 'App Type', '-')
            self.table.set(item, 'App Location', '-')
    

        event.widget.place_forget()  # Hide the combobox after selection

    def on_cell_double_click(self, event):
        cell = self.table.identify('item', event.x, event.y)
        if not cell:
            return
        
        
        column = self.table.identify_column(event.x)
        row = self.table.identify_row(event.y)
        
        column_name = self.table['columns'][int(column[1]) - 1]
        if column_name in ('Dump Type', 'App Type', 'App Location'):
            current_value = self.table.set(row, column)
            x, y, width, height = self.table.bbox(row, column)
            
            #combo_values = {
            #    'Dump Type': ['User', 'Kernel'],
            #    'App Type': ['64-bit', '32-bit'],
            #    'App Location': ['Client', 'Server']
            #}
            combo_values = {
                '#2': ['User', 'Kernel'],
                '#3': ['64-bit', '32-bit'],
                '#4': ['Client', 'Server']
            }
            
            combo = ttk.Combobox(self.table, values=combo_values[column], state='readonly')
            combo.set(current_value)
            combo.place(x=x, y=y, width=width, height=height)
            combo.bind('<<ComboboxSelected>>', lambda e, r=row, c=column: self.on_combo_select(e, r, c))
            combo.focus_set()
            combo.bind('<FocusOut>', lambda e: combo.place_forget())

    def show_combobox(self, event, combo):
        column = self.table.identify_column(event.x)
        row = self.table.identify_row(event.y)
        
        if column and row:
            x, y, width, height = self.table.bbox(row, column)
            combo.place(x=x, y=y, width=width, height=height)

    def launch_winDbg(self):
        if not self.dmp_files:
            messagebox.showwarning("Input Error", "No dumps selected.")
            return

        winDbg_count = sum(1 for proc in psutil.process_iter(['name']) if proc.info['name'] == 'windbg.exe')
        max_instances = 5

        if winDbg_count + len(self.dmp_files) > max_instances:
            messagebox.showwarning("Instance Limit Reached", f"Launching these dumps will exceed the instance limit ({max_instances}). \n\n You may want to close other instances of WinDbg before proceeding. \nIf not, instances will launch until they reach the limit.")

        for row, item in enumerate(self.table.get_children()):
            #memory_dump_path = self.table.set(item, 'File')
            memory_dump_path = self.dmp_files[row]
            dump_type = self.table.set(item, 'Dump Type')
            app_type = self.table.set(item, 'App Type')
            app_location = self.table.set(item, 'App Location')

            symbol_path = self.get_symbol_path(dump_type, app_type, app_location)
            command = f'WinDbg -z {memory_dump_path} -y srv*;{symbol_path} -c "!analyze -v"'

            try:
                winDbg_count = sum(1 for proc in psutil.process_iter(['name']) if proc.info['name'] == 'windbg.exe')
                if winDbg_count < max_instances:
                    subprocess.Popen(
                        command,
                        shell=True,
                        text=False,
                        cwd=self.winDbg_path,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                else:
                    messagebox.showwarning("Instance Limit Reached", f"Launching these dumps will exceed the instance limit ({max_instances}). Please close some instances before launching new ones.")
                    break

            except subprocess.CalledProcessError as e:
                messagebox.showerror("Execution Error", f"An error occurred:\n{e.output}")
    
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
            
            self.dmp_files.append(file_path)
            # Add the selected file to the table
            item_id = self.table.insert('', 'end', values=(os.path.basename(file_path), 'User', '64-bit', 'Client'))
            self.setup_item_dropdowns(item_id)
            
            # Show the table if it's hidden
            self.table_frame.grid()

    def get_backup_dump_path(self):
        default_backup_path = "//supportnas.graphon.com/support/Cases"
        
        if not os.path.exists(CONFIG_FILE_PATH):
            # First run, set the default symbol path
            if os.path.exists(default_backup_path):
                new_path = default_backup_path
            else:
                new_path = myUtils.select_dir("Select a secondary path for finding dumps...")

            config = {"backup_dump_path": new_path}
            with open(CONFIG_FILE_PATH, 'w') as config_file:
                json.dump(config, config_file)
            return new_path
        else:
            # Read the symbol path from the config file
            with open(CONFIG_FILE_PATH, 'r') as config_file:
                config = json.load(config_file)

            dump_path = config.get("backup_dump_path", "")
            if dump_path == "" or not os.path.exists(dump_path):
                dump_path = myUtils.select_dir("Select a secondary path for finding dumps...")
                config["backup_dump_path"] = dump_path
                with open(CONFIG_FILE_PATH, 'w') as config_file:
                    json.dump(config, config_file)
            
            return dump_path
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



    def get_symbol_path(self, dump_type, app_type, app_location):
        gg_version = self.go_global_var.get()
        if not gg_version or gg_version == "":
            return ""

        dump_type_path = "AttestationSigning_DisplayAudioDriver/DisplayDriver" if dump_type == "Kernel" else ""
        app_type_path = "devKit-x64Release" if app_type == "64-bit" else "devKit-Win32Release"
        app_location_path = app_location.lower()

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


if __name__ == "__main__":
    app = MemoryDumpAnalyzerApp()
    app.mainloop()