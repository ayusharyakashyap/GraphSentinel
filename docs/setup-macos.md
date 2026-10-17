# macOS Setup

## Prerequisites

- macOS with Docker Desktop running
- Python 3.11 or newer
- Node.js 20 or newer and npm

## Install and seed

Run from the repository root:

```sh
python3 --version
node --version
docker version
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
docker compose up -d
python -m graphsentinel.seed
```

The default FalkorDB port is 6379. If another local process uses it, set `FALKORDB_PORT=6380` in `.env`; Compose and the Python repository use the same setting. The database uses the named `falkordb-data` volume. Do not remove that volume unless you intend to erase its graph data.

## Start the API and frontend

Use two terminal windows from the repository root.

Terminal 1:

```sh
source .venv/bin/activate
python -m uvicorn graphsentinel.api:app --host 127.0.0.1 --port 8000
```

Terminal 2:

```sh
cd frontend
npm ci
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). FastAPI is at `http://127.0.0.1:8000`; OpenAPI docs are at `/docs`. The configured frontend CORS origin must exactly match `FRONTEND_ORIGIN` (default `http://localhost:5173`). Set `VITE_API_BASE_URL` in `frontend/.env.local` only if the API is hosted elsewhere.

## Run validation

From the repository root:

```sh
./.venv/bin/python -m pytest -q
./.venv/bin/python -m graphsentinel.evaluate --output docs/evaluation-results.json
```

From `frontend/`:

```sh
npm test
npm run build
```

The MCP server uses the same virtual environment and graph:

```sh
./.venv/bin/python -m graphsentinel.mcp_server
```

It communicates over stdio; configure it through your MCP host's command/args/env fields. See [MCP setup](mcp.md).

## Clean restart

Stop the API/frontend processes with Ctrl+C, then run:

```sh
docker compose restart falkordb
```

Start the two application processes again with the commands above. The named database volume preserves graph episodes and response audit records across the container restart.

## Reset only the demo graph

To intentionally replace the project demo graph with the checked-in fixture:

```sh
./.venv/bin/python -m graphsentinel.seed --reset-demo
```

The reset command only accepts the graph name `graphsentinel`; it does not remove the Docker volume.