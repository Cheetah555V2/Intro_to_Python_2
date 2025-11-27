import traceback
from datetime import datetime
import sys
import os

def error_handler(func):
    def inner(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            
            format_tb = traceback.format_tb(exc_traceback)
            
            # Create log directory if it doesn't exist
            log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'program', 'log')
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, f'{str(datetime.now())[:19].replace(":","_")}.log')
            
            with open(log_file, 'w') as file:
                file.write(f'{exc_type.__name__}\n')
                file.write(f'{exc_value}\n')
                for line in format_tb:
                    file.write(line)
                file.flush()
            
            # Show error message to user
            if 'tkinter' in sys.modules:
                from tkinter import messagebox
                messagebox.showerror("Error", f"{exc_type.__name__}: {exc_value}")
            
            return None

    return inner