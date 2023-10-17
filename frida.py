import os
import re
import shutil
import tkinter as tk
from tkinter import filedialog
import subprocess
import threading

original_libfrida_filename = None
source_apk_filename = None

def get_architecture():
    lib_path = os.path.join("temp", "lib")
    
    if os.path.exists(os.path.join(lib_path, "arm64-v8a")):
        return "arm64"
    elif os.path.exists(os.path.join(lib_path, "armeabi-v7a")):
        return "arm"
    else:
        return "unknown"

def get_new_architecture_folder(arch):
    if arch == "arm64":
        return "arm64-v8a"
    elif arch == "arm":
        return "armeabi-v7a"
    else:
        return "unknown"

def unpack_and_frida_gadget(file_path, source_apk_filename):
    try:
        message_display.config(state=tk.NORMAL)
        message_display.insert(tk.END, "searching for architecture...\n")
        apktool_jar = os.path.join("bin", "apktool.jar")
        output_dir = "temp"
        command = ["java", "-jar", apktool_jar, "d", file_path, "-o", output_dir]
        subprocess_info = subprocess.STARTUPINFO()
        subprocess_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        subprocess_info.wShowWindow = subprocess.SW_HIDE
        subprocess.run(command, check=True, startupinfo=subprocess_info)

        arch = get_architecture()
        message_display.config(state=tk.NORMAL)
        message_display.insert(tk.END, "arch =" + " " + arch + "\n")

        shutil.rmtree(output_dir)

        new_architecture = get_new_architecture_folder(arch)

        message_display.config(state=tk.NORMAL)
        message_display.insert(tk.END, "injecting frida-gadget...\n")
        frida_gadget_path = os.path.join("bin", "frida-gadget.exe")
        frida_gadget_command = [frida_gadget_path, "--arch", arch, file_path]
        subprocess_info = subprocess.STARTUPINFO()
        subprocess_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        subprocess_info.wShowWindow = subprocess.SW_HIDE
        subprocess.run(frida_gadget_command, check=True, startupinfo=subprocess_info)

        file_dir = os.path.dirname(file_path)
        file_name = os.path.basename(file_path)
        file_name_without_extension = os.path.splitext(file_name)[0]
        dist_dir = os.path.join(file_dir, file_name_without_extension, "dist")
        
        if os.path.exists(dist_dir):
            shutil.rmtree(dist_dir)
        else:
            message_display.config(state=tk.NORMAL)
            message_display.insert(tk.END, "Dist folder not found.\n")
        message_display.config(state=tk.DISABLED)

        file_dir = os.path.dirname(file_path)
        file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]
        lib_dir = os.path.join(file_dir, file_name_without_extension, "lib", new_architecture)

        for filename in os.listdir(lib_dir):
            if "libfrida" in filename and filename.endswith(".so"):
                global original_libfrida_filename
                original_libfrida_filename = os.path.splitext(filename)[0]

        for filename in os.listdir(lib_dir):
            if "libfrida" in filename:
                os.remove(os.path.join(lib_dir, filename))

        script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        libfrida_source_dir = os.path.join(script_dir, "bin")
        new_libfrida_path = os.path.join(lib_dir, "libfrda.so")

        if arch == "arm64":
            libfrida_source_path = os.path.join(libfrida_source_dir, "64-bit", "libfrda.so")
        elif arch == "arm":
            libfrida_source_path = os.path.join(libfrida_source_dir, "32-bit", "libfrda.so")
        else:
            message_display.config(state=tk.NORMAL)
            message_display.insert(tk.END, "Unknown architecture. libfrda.so not copied.\n")
            message_display.config(state=tk.DISABLED)
            return

        try:
            shutil.copy(libfrida_source_path, new_libfrida_path)
        except Exception as e:
            message_display.config(state=tk.NORMAL)
            message_display.insert(tk.END, f"Error copying libfrida.so: {e}\n")
        finally:
            message_display.config(state=tk.DISABLED)

        smali_dir = os.path.join(file_dir, file_name_without_extension, "smali")
        replace_libfrida_in_smali(smali_dir)

        frda_dir = os.path.join(file_dir, file_name_without_extension)
        rebuilt_apk_path = os.path.join(frda_dir, "rebuilt.apk")
        message_display.config(state=tk.NORMAL)
        message_display.insert(tk.END, "compiling...\n")
        command = ["java", "-jar", apktool_jar, "b", frda_dir, "-o", rebuilt_apk_path]
        subprocess_info = subprocess.STARTUPINFO()
        subprocess_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        subprocess_info.wShowWindow = subprocess.SW_HIDE
        subprocess.run(command, check=True, startupinfo=subprocess_info)
        message_display.config(state=tk.NORMAL)
        message_display.insert(tk.END, "compiled\n")

        bin_dir = os.path.join(script_dir, "bin")
        uber_apk_signer = os.path.join(bin_dir, "uber-apk-signer.bat")
        keystore_path = os.path.join(bin_dir, "testkey.jks")
        keystore_alias = "android"
        keystore_password = "android"
        key_password = "android"

        message_display.config(state=tk.NORMAL)
        message_display.insert(tk.END, "signing...\n")
        command = [uber_apk_signer, "--overwrite", "-a", rebuilt_apk_path, "--ks", keystore_path,
                   "--ksAlias", keystore_alias, "--ksKeyPass", key_password, "--ksPass", keystore_password]
        subprocess_info = subprocess.STARTUPINFO()
        subprocess_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        subprocess_info.wShowWindow = subprocess.SW_HIDE
        subprocess.run(command, check=True, startupinfo=subprocess_info)
        message_display.config(state=tk.NORMAL)
        message_display.insert(tk.END, "signed\n")

        CRACKED_dir = os.path.join(script_dir, "WITH_FRIDA")
        os.makedirs(CRACKED_dir, exist_ok=True)
        rebuilt_apk_destination = os.path.join(CRACKED_dir)
        shutil.move(rebuilt_apk_path, rebuilt_apk_destination)
        print("")

        file_dir = os.path.dirname(file_path)
        rebuilt_apk_path = os.path.join(CRACKED_dir, "rebuilt.apk")
        new_rebuilt_apk_path = os.path.join(CRACKED_dir, source_apk_filename)
        new_rebuilt_apk_path = os.path.normpath(new_rebuilt_apk_path)
        os.rename(rebuilt_apk_path, new_rebuilt_apk_path)

        shutil.rmtree(frda_dir)

        message_display.config(state=tk.NORMAL)
        message_display.insert(tk.END, "DONE\n")

    except subprocess.CalledProcessError:
        message_display.config(state=tk.NORMAL)
        message_display.insert(tk.END, "Can't inject frida-gadget\n")
        message_display.config(state=tk.NORMAL)
        message_display.insert(tk.END, "Open Console and type: pip install frida-gadget\n")
        message_display.config(state=tk.DISABLED)

def replace_libfrida_in_smali(directory):
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".smali"):
                file_path = os.path.join(root, filename)

                with open(file_path, "r") as file:
                    smali_content = file.read()

                lib_stripped = original_libfrida_filename.lstrip("lib")

                updated_content = smali_content.replace(lib_stripped, "frda")

                with open(file_path, "w") as file:
                    file.write(updated_content)

def select_apk():
    global source_apk_filename
    file_path = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
    if file_path:
        source_apk_filename = os.path.basename(file_path)

        message_display.config(state=tk.NORMAL)
        message_display.delete("1.0", tk.END)
        message_display.config(state=tk.DISABLED)

        threading.Thread(target=unpack_and_frida_gadget, args=(file_path, source_apk_filename), daemon=True).start()

root = tk.Tk()
root.title("Frida-Gadget injector")
root.geometry("400x300")

select_button = tk.Button(root, text="Select .apk", command=select_apk)
select_button.pack(pady=10)

message_display = tk.Text(root, bg="white", wrap=tk.WORD, state=tk.DISABLED)
message_display.pack(fill=tk.BOTH, expand=True)

root.mainloop()