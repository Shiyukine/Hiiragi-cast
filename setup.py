# run command in python
import os
import sys

if __name__ == "__main__":
    os.system(f"{sys.executable} -m pip install -r requirements.txt")
    os.system(f"cd electron-player && npm install")

    print("="*90)
    print("WARNING: In order to run video in Electron, you must sign the Electron executable with a valid certificate.")
    print("To create a signed certificate, you must create an account on Castlabs EVS.")
    print("If you are unsure how to do this, please refer to the documentation: https://github.com/castlabs/electron-releases/wiki/EVS")
    print("If you do not sign the executable, video playback might not work on Windows and macOS.")
    print("="*90)
    have_evs_acc = input("Do you have a Castlabs EVS account? (Note: If you say no, you will be asked to sign up.) ([y]/n): ")

    if have_evs_acc.lower() in ["n", "no"]:
        os.system(f"{sys.executable} -m castlabs_evs.account signup")

    if sys.platform == "win32":
        os.system(f"{sys.executable} -m castlabs_evs.vmp sign-pkg .\\electron-player\\node_modules\\electron\\dist")
    elif sys.platform == "darwin":
        os.system(f"{sys.executable} -m castlabs_evs.vmp sign-pkg ./electron-player/node_modules/electron/dist/Electron.app")

    os.system(f"{sys.executable} main.py")