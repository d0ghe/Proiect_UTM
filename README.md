# Proiect_UTM

Proiect_UTM is a local security platform with a dashboard for system telemetry, hosts-based content filtering, antivirus workflows, quarantine management, platform details, cleanup tools, event tracking, and Hybrid Analysis / Falcon Sandbox integrations.

It is designed to give you a single place where you can monitor the machine, run scans, review recent security activity, and use external malware-analysis providers when they are configured.

## Highlights

- live dashboard with CPU, RAM, GPU, network, and platform information
- hosts-based content filtering for adult content, ads, malware, gambling, piracy, social media, and bypass domains
- protection workflow with local heuristic scanning, quarantine, recent results, and provider status
- Hybrid Analysis quick scans and Falcon Sandbox submission support
- platform tools for OS details, network monitoring, and cleanup actions
- events and activity history ordered for fast review
- encrypted project secret storage with a local passphrase instead of a committed plain-text API key

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
PROJECT_SECRET_PASSPHRASE=choose_a_local_passphrase
HYBRID_ANALYSIS_API_KEY=your_key_here
HYBRID_ANALYSIS_ENABLED=true
HYBRID_ANALYSIS_BASE_URL=https://hybrid-analysis.com/api/v2
HYBRID_ANALYSIS_REQUEST_TIMEOUT_MS=60000
HYBRID_ANALYSIS_ENVIRONMENT_ID=160
```

To move the Hybrid Analysis key out of plain text after you add it once:

```powershell
cd backend
npm run secrets:migrate
```

That command:

- encrypts supported secrets into `backend/config/secrets.enc.json`
- removes the plain-text secret keys from `backend/.env`
- keeps only `PROJECT_SECRET_PASSPHRASE` in `backend/.env`

The encrypted file can stay in the project. The passphrase must stay local to each machine.

## API Key Notice

Hybrid Analysis quick scans, Falcon Sandbox submissions, and any related external analysis features require your own Hybrid Analysis API key.

The repository can now keep encrypted provider secrets in `backend/config/secrets.enc.json`, but the local passphrase still must not be committed. Hybrid Analysis and any related provider features will not work until you add your own credentials and unlock them locally.

## Content Filtering

The Content Filtering tab applies real blocking by writing a managed section into the OS hosts file.

- Windows and Linux are the primary targets
- macOS hosts-path support is included as a best-effort path
- applying or removing the hosts policy usually requires running the backend with administrator or root privileges
- hosts-based blocking is system-wide, but it does not wildcard every possible subdomain the way a dedicated DNS proxy would

## Development Notes

- `backend/.env` is intentionally ignored by git and should never be committed
- `backend/config/secrets.enc.json` may be committed, but `PROJECT_SECRET_PASSPHRASE` must stay local
- `backend/.env.example` should stay committed as the setup template
- if external provider features appear unavailable, first check that your backend has the required API key configured
- `start-platform.ps1` is the single startup script for bootstrapping and launching the project on Windows
