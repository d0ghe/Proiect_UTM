# Proiect_UTM

## Fresh Start

Clone the repo again if you delete the local copy:

```powershell
git clone https://github.com/d0ghe/Proiect_UTM
cd Proiect_UTM
.\start-platform.cmd
```

The script will:

- install missing `backend` and `frontend` dependencies
- stop anything already using ports `5000` and `5173`
- start the backend on `http://localhost:5000`
- start the frontend on `http://localhost:5173`

Useful options:

```powershell
.\start-platform.cmd -ForceInstall
.\start-platform.cmd -SkipInstall
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1 -DryRun
```
