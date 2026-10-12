# HUNTR verification gate. `make verify` is the Phase-0 robustness exit gate:
# it must pass before anything ships. CI runs the same checks (.github/workflows/ci.yml).

.PHONY: verify test e2e compile

verify: compile test e2e ## full gate: byte-compile + unit/integration tests + browser E2E
	@echo "verify: all checks passed"

compile: ## byte-compile every tool + the server (catches syntax/latent errors)
	python3 -m compileall -q tools huntr-server.py

test: ## unit + server-hardening integration tests
	python3 -m unittest discover -s tests -p "test_*.py"

e2e: ## browser E2E against a live server (auto-booted by Playwright)
	cd e2e && (npm ci || npm install) && npx playwright install chromium >/dev/null 2>&1 || true
	cd e2e && npx playwright test --reporter=line
