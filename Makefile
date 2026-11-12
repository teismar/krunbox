.PHONY: help install test test-fast validate check ci ci-fast ci-dryrun pkg-python pkg-deb pkg-rpm pkg ui doctor docs-install docs-build docs-serve clean

PYTHON ?= python3
XVFB ?= xvfb-run -a
PORT ?= 4711

help: ## Show available Makefile targets
	@echo "krunbox development commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Install krunbox in editable mode with development dependencies
	$(PYTHON) -m pip install -e ".[dev]"

validate: ## Validate Desktop file, AppStream metainfo, and icon cache
	desktop-file-validate krunbox/data/io.krunbox.Krunbox.desktop
	appstreamcli validate --no-net krunbox/data/io.krunbox.Krunbox.metainfo.xml
	gtk4-update-icon-cache -q -t -f krunbox/data/icons

test: ## Run the full pytest test suite under virtual display (Xvfb)
	$(XVFB) $(PYTHON) -m pytest -v tests/

test-fast: ## Run the pytest test suite in quiet mode
	$(XVFB) $(PYTHON) -m pytest -q tests/

check: validate test ## Run all validations and the full test suite (same as CI)

ci: ## Run GitHub Actions CI test job locally via act
	act push -j test

ci-fast: ## Run a single Python matrix job via act
	act push -j test --matrix python-version:3.12

ci-dryrun: ## Dry-run and validate all GitHub Actions workflows locally with act
	act -n

pkg-python: ## Build Python source distribution and wheel
	$(PYTHON) -m build

pkg-deb: ## Build Debian/Ubuntu .deb package
	./packaging/build-deb.sh

pkg-rpm: ## Build Fedora/RHEL .rpm package
	./packaging/build-rpm.sh

pkg: pkg-python pkg-deb pkg-rpm ## Build all packages (wheel, sdist, deb, rpm)

ui: ## Launch the native GTK4 / Libadwaita console locally
	$(PYTHON) -m krunbox.ui.app

doctor: ## Run system and virtualization diagnostics
	$(PYTHON) -m krunbox.cli.main doctor

docs-install: ## Install documentation website dependencies
	cd website && npm install

docs-build: ## Build the Docusaurus documentation website
	cd website && npm run build

docs-serve: ## Serve the documentation website locally (default port 4711)
	cd website && npx docusaurus serve --port $(PORT) --host 0.0.0.0

clean: ## Clean up build artifacts, cache files, and test caches
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov 2>/dev/null || sudo rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
