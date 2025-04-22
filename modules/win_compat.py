"""
Windows compatibility module for RedTriage
Handles specific issues with click package on Windows with Python 3.12+
Created by: Zarni (Neo)
"""

import sys
import platform
import os

def patch_click_for_windows():
    """
    Patch the click package for Windows when using Python 3.12+
    This addresses the ModuleNotFoundError: No module named 'click._winconsole' issue
    """
    if platform.system() != "Windows":
        return
    
    # Only needed for Python 3.12+
    if sys.version_info < (3, 12):
        return
    
    try:
        import click
        import click._winconsole
    except ImportError:
        # Check if click is installed
        try:
            import click
        except ImportError:
            print("Error: Required package 'click' not found. Install it using 'pip install click>=8.1.7'")
            sys.exit(1)
        
        # If click is installed but _winconsole is missing, create a temporary solution
        click_path = os.path.dirname(click.__file__)
        
        # Create stub _winconsole module if it doesn't exist
        winconsole_path = os.path.join(click_path, "_winconsole.py")
        if not os.path.exists(winconsole_path):
            try:
                with open(winconsole_path, 'w') as f:
                    f.write("""
# Stub _winconsole module for Python 3.12+ compatibility
def _get_windows_console_stream(f, encoding, errors):
    import io
    return io.TextIOWrapper(f, encoding=encoding, errors=errors)
                    """)
                print("Created compatibility fix for click package on Windows with Python 3.12+")
            except Exception as e:
                print(f"Warning: Could not create compatibility fix: {e}")
                print("Try running this script with administrator privileges") 