#!/usr/bin/env python3
import os,pathlib,shutil,subprocess
folder=pathlib.Path(os.environ.get('RUNNER_TEMP','/tmp'))/'tunnelnest-signing'
if os.name!='nt' and (folder/'build.keychain-db').exists():subprocess.run(['security','delete-keychain',str(folder/'build.keychain-db')],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
shutil.rmtree(folder,ignore_errors=True)
