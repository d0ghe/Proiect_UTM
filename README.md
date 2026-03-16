# Proiect_UTM

Proiect_UTM is a local security platform with a dashboard for system telemetry, antivirus workflows, quarantine management, platform details, cleanup tools, event tracking, and Hybrid Analysis / Falcon Sandbox integrations.

It is designed to give you a single place where you can monitor the machine, run scans, review recent security activity, and use external malware-analysis providers when they are configured.

## Highlights

- live dashboard with CPU, RAM, GPU, network, and platform information
- protection workflow with local heuristic scanning, quarantine, recent results, and provider status
- Hybrid Analysis quick scans and Falcon Sandbox submission support
- platform tools for OS details, network monitoring, and cleanup actions
- events and activity history ordered for fast review

## Quick Start

```powershell
git clone https://github.com/d0ghe/Proiect_UTM
cd Proiect_UTM
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1
```

The startup script will:

- install Node.js LTS automatically when it is missing and a supported package manager is available
- install missing `backend` and `frontend` dependencies
- create `backend/.env` from `backend/.env.example` when needed
- stop anything already using ports `5000` and `5173`
- start the backend on `http://localhost:5000`
- start the frontend on `http://localhost:5173`

Useful options:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1 -ForceInstall
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1 -SkipInstall
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1 -SkipNodeInstall
```

## Configuration

The project keeps `backend/.env.example` in the repo as a safe template.  
Create your own local `backend/.env` file from it on each machine.

Example:

```env
HYBRID_ANALYSIS_API_KEY=your_key_here
HYBRID_ANALYSIS_ENABLED=true
HYBRID_ANALYSIS_BASE_URL=https://hybrid-analysis.com/api/v2
HYBRID_ANALYSIS_REQUEST_TIMEOUT_MS=60000
HYBRID_ANALYSIS_ENVIRONMENT_ID=160
```

## API Key Notice

Hybrid Analysis quick scans, Falcon Sandbox submissions, and any related external analysis features require your own Hybrid Analysis API key.

The repository does not include a real key, and these features will not work on a new machine until you add your own credentials to `backend/.env` or set them as environment variables locally.

## Development Notes

- `backend/.env` is intentionally ignored by git and should never be committed
- `backend/.env.example` should stay committed as the setup template
- if external provider features appear unavailable, first check that your backend has the required API key configured
- `start-platform.ps1` is the single startup script for bootstrapping and launching the project on Windows
