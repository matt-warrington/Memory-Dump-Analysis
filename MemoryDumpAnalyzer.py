# Memory Dump Analyzer Application

# This program is designed to analyze memory dump files using WinDbg. 
# It allows users to load memory dump files, select dump types, app types, and app locations, and launch WinDbg to analyze the dumps.
# WinDbg will be launched for each dump with the symbols necessary based on the above-mentioned fields, as well as the GO-Global version selected by the user. 

# To create an executable file for this program:
# 1. Install PyInstaller using pip: pip install pyinstaller
# 2. Navigate to the directory containing the script (MemoryDumpAnalyzer.py) in the command line.
# 3. Run the following command to create an executable:
#    pyinstaller --onefile MemoryDumpAnalyzer.py
# 4. PyInstaller will create a 'dist' folder with the executable file inside. The executable can be run independently on Windows systems.


from functools import wraps
import json
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import GOGlobal
import os
import myUtils
import psutil
import zipfile
import zlib
import bz2
import lzma

CONFIG_FILE_PATH = "config.json"
DEFAULT_WINDBG_PATH = "C:/Program Files (x86)/Windows Kits/10/Debuggers/x86"
MAX_WINDBG_INSTANCES = 10

class MemoryDumpAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.symbol_base_path = self.get_symbol_base_path()
        self.symbol_base_path_backup = self.get_symbol_base_path_backup()
        self.dump_base_path = self.get_dump_base_path()
        self.dump_base_path_backup = self.get_dump_base_path_backup()
        self.winDbg_path = self.get_winDbg_path()

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

    def protect_path(func):
        '''
        The point of this is to prevent certain functions (e.g. unzip_files()) from running on network folders.
        I don't think there is any possibility of this at the current stage of the project anyway, but worth checking to be safe.
        '''
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Would the check for "//" be enough to ensure we can't run an operation on a network path? 
            # The check for ".graphon.com" might be overkill but I thought better safe than sorry.
            if any(".graphon.com" in arg for arg in args if isinstance(arg, str)) or any("//" in arg for arg in args if isinstance(arg, str)):
                raise PermissionError(f"Operation not allowed on protected path: {self.shared_folder_path}")
            return func(self, *args, **kwargs)
        return wrapper

    def createWidgets(self):
        self.case_number_label = tk.Label(self, text="Add Dump(s) by Case Number: ")
        self.case_number_label.grid(column=0, row=0, padx=10, pady=5, sticky='w')
        self.case_number_entry = tk.Entry(self, width=50)
        self.case_number_entry.grid(column=1, row=0, padx=10, pady=5, sticky='ew')
        self.find_dump_button = tk.Button(self, text="Get Dump(s)", command=self.find_dmp_files)
        self.find_dump_button.grid(column=2, row=0, padx=10, pady=5, sticky='ew')
        
        # Memory Dump
        self.memory_dump_label = tk.Label(self, text="Add individual memory dump: ")
        self.memory_dump_label.grid(column=0, row=1, padx=10, pady=5, sticky='w')

        self.memory_dump_entry = tk.Entry(self, width=30)
        self.memory_dump_entry.grid(column=1, row=1, padx=10, pady=5, sticky='ew')

        self.browse_button = tk.Button(self, text="Browse...", command=self.browse_file)
        self.browse_button.grid(column=2, row=1, padx=10, pady=5, sticky='ew')
        
        # GO-Global Version
        self.go_global_label = tk.Label(self, text="GO-Global Version: ")
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
        self.table.bind('<<TreeviewSelect>>', self.on_table_select)
        self.table_frame.grid_remove() # Hide the table initially

        # Individual launch button
        self.launch_winDbg_indy_button = tk.Button(self, text="Launch Dump", command=self.launch_winDbg_indy)
        self.launch_winDbg_indy_button.grid(column=0, row=4, padx=10, pady=10, sticky='ew')
        self.launch_winDbg_indy_button.config(state=tk.DISABLED)

        # Launch WinDbg Button
        self.launch_winDbg_button = tk.Button(self, text="Launch All Dumps", command=self.launch_winDbg)
        self.launch_winDbg_button.grid(column=1, row=4, padx=10, pady=10, sticky='ew')
        self.launch_winDbg_button.config(state=tk.DISABLED)

        # Clear Table button
        self.clear_button = tk.Button(self, text="Clear Table", command=self.clear_table)
        self.clear_button.grid(column=2, row=4, padx=10, pady=10, sticky='ew')

    def clear_table(self):
        # Clear the table
        for item in self.table.get_children():
            self.table.delete(item)
        # Reset the dmp_files list
        self.dmp_files = []

    def on_table_select(self, event):
        selected_items = self.table.selection()
        if selected_items:
            self.launch_winDbg_indy_button.config(state=tk.NORMAL)
        else:
            self.launch_winDbg_indy_button.config(state=tk.DISABLED)

    def get_winDbg_path(self):
        """
        Returns the path to the WinDbg executable by checking the default path, then the config file path. If the config file path does not yet exist, the user selects a new one. 
        """
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
    

    @protect_path
    def find_dmp_files(self):
        def search_for_dmp_files(base_path, found_files=set()):
            dmp_files = []

            for root, dirs, files in os.walk(base_path):
                for file in files:
                    file_lower = file.lower()
                    full_path = os.path.join(root, file)
                    if full_path in found_files:
                        continue
                    if file_lower.endswith('.dmp'):
                        dmp_files.append(full_path)
                        found_files.add(full_path)
                    elif file_lower.endswith('.zip'):
                        zip_base_name = os.path.splitext(file)[0]
                        extract_to = os.path.join(root, zip_base_name)
                        
                        if not os.path.exists(extract_to):
                            os.makedirs(extract_to)
                            self.unzip_files(full_path, extract_to)
                        
                        dmp_files.extend(search_for_dmp_files(extract_to, found_files))

            return dmp_files

        case_number = self.case_number_entry.get()
        if not case_number:
            case_selected = myUtils.select_dir(initialDir=self.dump_base_path)
            if not case_selected:
                self.dmp_files = []
                return
            case_number = os.path.basename(case_selected)
        else:
            case_selected = ""

        primary_path = os.path.join(self.dump_base_path, case_number)
        secondary_path = os.path.join(self.dump_base_path_backup, case_number)

        if case_selected and case_selected != primary_path:
            try:
                shutil.copytree(case_selected, primary_path, dirs_exist_ok=True)
            except Exception as e:
                messagebox.showwarning(
                    "Exception thrown",
                    f"{type(e).__name__} when copying from {case_selected}:\n\n{str(e)}"
                )

        if not os.path.isdir(primary_path) and os.path.isdir(secondary_path):
            try:
                shutil.copytree(secondary_path, primary_path, dirs_exist_ok=True)
            except Exception as e:
                messagebox.showwarning(
                    "Exception thrown",
                    f"{type(e).__name__} when copying from {secondary_path}:\n\n{str(e)}"
                )

        if os.path.isdir(primary_path):
            self.dmp_files = search_for_dmp_files(primary_path)

        if self.dmp_files:
            self.populate_table()
        else:
            messagebox.showwarning(
                "No dumps found",
                f"No dumps found in any path. \n\n{primary_path}\n{secondary_path}"
            )

    # Helper function to unzip files
    @protect_path
    def unzip_files(self, zip_path, extract_to):
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
                            #elif file_info.compress_type == 9:  # Custom handling for compression type 9
                                # Attempt extraction using 7z for unsupported compression methods
                                #subprocess.run(['7z', 'x', '-o' + extract_to, zip_path], check=True)
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
                                                f"Compression type: {file_info.compress_type}\n"
                                                "Manually unzip the file and then select the dump file.")
                            extract_to = myUtils.select_file("DMP. ", initialDir=os.path.dirname(zip_path), fileTypeExt="*.*")
                            
                            # Copy contents of the unzipped directory to the new dir

            
            #print(f"Extraction of {zip_path} completed.")
        except zipfile.BadZipFile:
            file_name = os.path.basename(zip_path)
            messagebox.showerror("Invalid Zip File", 
                                f"The file '{file_name}' is not a valid zip file or is corrupted.")
        except Exception as e:
            file_name = os.path.basename(zip_path)
            messagebox.showerror("Error", f"An error occurred while extracting '{file_name}': {str(e)}")

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
        # Enable the launch buttons when dumps are loaded
        self.launch_winDbg_button.config(state=tk.NORMAL)

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
        

        if winDbg_count + len(self.dmp_files) > MAX_WINDBG_INSTANCES:
            messagebox.showwarning("Instance Limit Reached", f"Launching these dumps will exceed the instance limit ({MAX_WINDBG_INSTANCES}). \n\n You may want to close other instances of WinDbg before proceeding. \nIf not, instances will launch until they reach the limit.")

        for row, item in enumerate(self.table.get_children()):
            memory_dump_path = self.dmp_files[row]
            dump_type = self.table.set(item, 'Dump Type')
            app_type = self.table.set(item, 'App Type')
            app_location = self.table.set(item, 'App Location')

            symbol_path = self.get_symbol_path(dump_type, app_type, app_location)
            command = f'WinDbg -z {memory_dump_path} -y srv*;{symbol_path} -c "!analyze -v"'

            try:
                winDbg_count = sum(1 for proc in psutil.process_iter(['name']) if proc.info['name'] == 'windbg.exe')
                if winDbg_count < MAX_WINDBG_INSTANCES:
                    subprocess.Popen(
                        command,
                        shell=True,
                        text=False,
                        cwd=self.winDbg_path,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                else:
                    messagebox.showwarning("Instance Limit Reached", f"Launching these dumps will exceed the instance limit ({MAX_WINDBG_INSTANCES}). Please close some instances before launching new ones.")
                    break

            except subprocess.CalledProcessError as e:
                messagebox.showerror("Execution Error", f"An error occurred:\n{e.output}")
    
    def launch_winDbg_indy(self):
        if not self.dmp_files:
            messagebox.showwarning("Input Error", "No dumps selected.")
            return
        
        winDbg_count = sum(1 for proc in psutil.process_iter(['name']) if proc.info['name'] == 'windbg.exe')
        if winDbg_count + 1 > MAX_WINDBG_INSTANCES:
            messagebox.showwarning("Instance Limit Reached", f"Launching this dump will exceed the instance limit ({MAX_WINDBG_INSTANCES}). \n\n You may want to close other instances of WinDbg before proceeding. \nIf not, instances will launch until they reach the limit.")

        selected_item = self.table.focus()  # Get the selected item from the table
        if selected_item:
            memory_dump_path = self.dmp_files[self.table.index(selected_item)]
            dump_type = self.table.set(selected_item, 'Dump Type')
            app_type = self.table.set(selected_item, 'App Type')
            app_location = self.table.set(selected_item, 'App Location')

            symbol_path = self.get_symbol_path(dump_type, app_type, app_location)
            command = f'WinDbg -z {memory_dump_path} -y srv*;{symbol_path} -c "!analyze -v"'

            try:
                if winDbg_count < MAX_WINDBG_INSTANCES:
                    subprocess.Popen(
                        command,
                        shell=True,
                        text=False,
                        cwd=self.winDbg_path,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                else:
                    messagebox.showwarning("Instance Limit Reached", f"Launching this dump will exceed the instance limit ({MAX_WINDBG_INSTANCES}). Please close some instances before launching new ones.")

            except subprocess.CalledProcessError as e:
                messagebox.showerror("Execution Error", f"An error occurred:\n{e.output}")

    def get_go_global_versions(self):
        versions = GOGlobal.versions
        if os.path.exists(self.symbol_base_path):
            versions.extend([d for d in os.listdir(self.symbol_base_path) if os.path.isdir(os.path.join(self.symbol_base_path, d))])
        
        def sort_versions(version_list):
            def version_key(version):
                try:
                    return (0, [int(part) for part in version.split('.')])
                except ValueError:
                    # If conversion fails, return a tuple with 1 as the first element
                    # This ensures incorrectly formatted versions are sorted alphabetically
                    # after the correctly formatted ones
                    return (1, version)
            
            return sorted(version_list, key=version_key)

        return sort_versions(versions)

    def browse_file(self):
        file_path = myUtils.select_file("DMP", "*.dmp", self.dump_base_path)
        if file_path:
            self.memory_dump_entry.delete(0, tk.END)
            self.memory_dump_entry.insert(0, file_path)
            
            self.dmp_files.append(file_path)
            
            # Add the selected file to the table
            self.populate_table()

    def get_dump_base_path_backup(self):
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
            # Read the dump path from the config file
            with open(CONFIG_FILE_PATH, 'r') as config_file:
                config = json.load(config_file)

            dump_path = config.get("backup_dump_path", "")
            if dump_path == "" or not os.path.exists(dump_path):
                dump_path = myUtils.select_dir("Select a secondary path for finding dumps...")
                config["backup_dump_path"] = dump_path
                with open(CONFIG_FILE_PATH, 'w') as config_file:
                    json.dump(config, config_file)
            
            return dump_path
        
    def get_symbol_base_path_backup(self):
        default_backup_path = "//qnapnas.graphon.com/Builds/"
        
        if not os.path.exists(CONFIG_FILE_PATH):
            # First run, set the default symbol path
            if os.path.exists(default_backup_path):
                new_path = default_backup_path
            else:
                new_path = myUtils.select_dir("Select a secondary path for finding symbols...")

            config = {"backup_symbol_path": new_path}
            with open(CONFIG_FILE_PATH, 'w') as config_file:
                json.dump(config, config_file)
            return new_path
        else:
            # Read the symbol path from the config file
            with open(CONFIG_FILE_PATH, 'r') as config_file:
                config = json.load(config_file)

            symbol_path = config.get("backup_symbol_path", "")
            if symbol_path == "" or not os.path.exists(symbol_path):
                symbol_path = myUtils.select_dir("Select a secondary path for finding symbols...")
                config["backup_symbol_path"] = symbol_path
                with open(CONFIG_FILE_PATH, 'w') as config_file:
                    json.dump(config, config_file)
            
            return symbol_path

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
        if not gg_version:
            return ""

        dump_type_path = "AttestationSigning_DisplayAudioDriver/DisplayDriver" if dump_type == "Kernel" else ""
        app_type_path = "devKit-x64Release" if app_type == "64-bit" else "devKit-Win32Release"
        app_location_path = app_location.lower()

        symbol_path = os.path.join(self.symbol_base_path, gg_version)
        if dump_type_path:
            symbol_path = os.path.join(symbol_path, dump_type_path)
        else:
            symbol_path = os.path.join(symbol_path, app_type_path, "Release", app_location_path)

        if myUtils.unzip_path(symbol_path):
            return symbol_path
        elif self.get_symbols_from_backup_path(gg_version):
            if os.path.exists(symbol_path):
                return symbol_path
        
        messagebox.showwarning("Path Not Found", f"No symbols found at {symbol_path}. \n\nPlease find the symbols you are looking for and upload the path here.")
        return ""

    def get_symbols_from_backup_path(self, version):
        """
        Search for a directory named version by traversing the directory tree directly.
        """

        root_path = self.symbol_base_path_backup
        
        # Extract the major, minor, patch, and build numbers from the version string
        parts = version.split('.')
        if len(parts) != 4:
            print("Invalid version format. Please provide version in the form of x.x.x.xxxxx")
            return None

        major_minor_patch = '.'.join(parts[:3])
        build = int(parts[3])

        # Determine the subdirectory range
        subdirectory_range = f"{(build // 100) * 100}-{(build // 100) * 100 + 99}"

        # Construct the expected path
        expected_path = os.path.join(root_path, major_minor_patch, subdirectory_range, version)

        if os.path.isdir(expected_path):
            shutil.copytree(expected_path, self.symbol_base_path)
            return myUtils.unzip_path(self.symbol_base_path)
        else:
            return False


if __name__ == "__main__":
    app = MemoryDumpAnalyzerApp()
    app.mainloop()