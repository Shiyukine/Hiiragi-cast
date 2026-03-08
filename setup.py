# run command in python
import os
import sys
import stat
import subprocess
import ssl

STAT_0o775 = ( stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
             | stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP
             | stat.S_IROTH |                stat.S_IXOTH )

if __name__ == "__main__":
    os.system(f"{sys.executable} -m pip install -r requirements.txt")
    os.system(f"cd electron-player && npm install")

    if sys.platform == "win32" or sys.platform == "darwin":
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
            os.system(f"{sys.executable} -m castlabs_evs.vmp sign-pkg ./electron-player/node_modules/electron/dist/")

    current_dir = os.getcwd()

    if sys.platform == "darwin":
        # source: https://github.com/python/cpython/blob/560ea272b01acaa6c531cc7d94331b2ef0854be6/Mac/BuildScript/resources/install_certificates.command
        openssl_dir, openssl_cafile = os.path.split(
        ssl.get_default_verify_paths().openssl_cafile)

        print(" -- pip install --upgrade certifi")
        subprocess.check_call([sys.executable,
            "-E", "-s", "-m", "pip", "install", "--upgrade", "certifi"])

        import certifi

        # change working directory to the default SSL directory
        os.chdir(openssl_dir)
        relpath_to_certifi_cafile = os.path.relpath(certifi.where())
        print(" -- removing any existing file or link")
        try:
            os.remove(openssl_cafile)
        except FileNotFoundError:
            pass
        print(" -- creating symlink to certifi certificate bundle")
        os.symlink(relpath_to_certifi_cafile, openssl_cafile)
        print(" -- setting permissions")
        os.chmod(openssl_cafile, STAT_0o775)
        print(" -- update complete")

        os.chdir(current_dir)

    os.system(f"{sys.executable} main.py")