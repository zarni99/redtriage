"""
Windows compatibility module for RedTriage
Handles specific issues with click package on Windows with Python 3.12+
Created by: Zarni (Neo)
"""

import sys
import platform
import os
import subprocess

def install_package(package_name):
    """
    Install a Python package using pip
    """
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        return True
    except subprocess.CalledProcessError:
        return False

def patch_click_for_windows():
    """
    Patch the click package for Windows when using Python 3.12+
    This addresses the ModuleNotFoundError: No module named 'click._winconsole' issue
    """
    if platform.system() != "Windows":
        return
    
    # First make sure click package is installed
    try:
        import click
    except ImportError:
        print("Required package 'click' not found. Attempting to install...")
        
        # Try different versions in case one fails
        for version in ["click==8.1.7", "click==8.1.6", "click==8.1.3", "click"]:
            print(f"Trying to install {version}...")
            if install_package(version):
                print(f"Successfully installed {version}")
                try:
                    import click
                    break
                except ImportError:
                    continue
        else:
            print("Error: Failed to install click package. Please install it manually:")
            print("pip install --user click==8.1.7")
            sys.exit(1)
    
    # Only needed for Python 3.12+
    if sys.version_info < (3, 12):
        return
    
    try:
        import click._winconsole
    except ImportError:
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
                
                # Now let's make sure we can import it
                try:
                    sys.path.insert(0, click_path)
                    import _winconsole
                    sys.path.pop(0)
                    print("Successfully loaded the compatibility module")
                except ImportError:
                    print("Warning: Created compatibility file but still unable to import it.")
                    print("You may need to run this script with administrator privileges.")
            except Exception as e:
                print(f"Warning: Could not create compatibility fix: {e}")
                print("Try running this script with administrator privileges")
                print("\nAlternatively, you can manually create a file at this location:")
                print(f"{winconsole_path}")
                print("With this content:")
                print('def _get_windows_console_stream(f, encoding, errors):')
                print('    import io')
                print('    return io.TextIOWrapper(f, encoding=encoding, errors=errors)') 