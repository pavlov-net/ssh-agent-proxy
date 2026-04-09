# op-sign-proxy — Makefile
#
# Most of the value here is the systemd user-service install lifecycle
# (install-systemd, uninstall-systemd, status, logs). The build / test /
# vet targets are thin aliases for muscle memory — call `go` directly if
# you prefer.
#
# Run `make` or `make help` to see all targets.

SHELL := /bin/bash

# --- Paths --------------------------------------------------------------
# Override on the command line, e.g. `make install BINDIR=/usr/local/bin`.
BINDIR           ?= $(HOME)/.local/bin
CONFIG_DIR       ?= $(HOME)/.config/op-sign-proxy
SYSTEMD_USER_DIR ?= $(HOME)/.config/systemd/user
PROXY_URL        ?= http://127.0.0.1:7221

UNIT_SRC  := contrib/systemd/op-sign-proxy.service
UNIT_DEST := $(SYSTEMD_USER_DIR)/op-sign-proxy.service
ENV_SRC   := contrib/systemd/env.example
ENV_DEST  := $(CONFIG_DIR)/env

# --- Go targets ---------------------------------------------------------

.PHONY: build
build: ## Build the op-sign-proxy binary into ./bin/
	@mkdir -p bin
	go build -o bin/op-sign-proxy .

.PHONY: test
test: ## Run the full test suite
	go test ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: check
check: vet test ## Run go vet and go test

.PHONY: clean
clean: ## Remove built artifacts
	rm -rf bin

# --- Install / systemd lifecycle ---------------------------------------

.PHONY: install
install: build ## Install the binary into $(BINDIR) (default ~/.local/bin)
	install -d -m 0755 $(BINDIR)
	install -m 0755 bin/op-sign-proxy $(BINDIR)/op-sign-proxy
	@echo "Installed $(BINDIR)/op-sign-proxy"

.PHONY: install-systemd
install-systemd: install ## Install binary + systemd user unit + env template, then reload
	install -d -m 0700 $(CONFIG_DIR)
	@if [ -e $(ENV_DEST) ]; then \
		echo "Keeping existing $(ENV_DEST) (contains secrets; edit manually)"; \
	else \
		install -m 0600 $(ENV_SRC) $(ENV_DEST); \
		echo "Wrote $(ENV_DEST) from template"; \
	fi
	install -d -m 0755 $(SYSTEMD_USER_DIR)
	install -m 0644 $(UNIT_SRC) $(UNIT_DEST)
	systemctl --user daemon-reload
	@echo
	@echo "Next steps:"
	@echo "  1. Edit $(ENV_DEST) to set OP_SERVICE_ACCOUNT_TOKEN and OP_SSH_KEY_REF"
	@echo "  2. systemctl --user enable --now op-sign-proxy.service"
	@echo "  3. Under WSL2 (first time only): sudo loginctl enable-linger \$$USER"

.PHONY: uninstall-systemd
uninstall-systemd: ## Stop, disable, and remove the systemd user unit (env file preserved)
	-systemctl --user disable --now op-sign-proxy.service
	rm -f $(UNIT_DEST)
	systemctl --user daemon-reload
	@echo "Removed $(UNIT_DEST)"
	@echo "$(ENV_DEST) preserved (contains secrets). Delete manually if desired."

.PHONY: status
status: ## systemctl --user status op-sign-proxy
	systemctl --user status op-sign-proxy.service

.PHONY: logs
logs: ## journalctl --user -u op-sign-proxy -f
	journalctl --user -u op-sign-proxy.service -f

.PHONY: pubkey
pubkey: ## Fetch the public key from a running proxy
	@curl --silent --show-error --fail $(PROXY_URL)/publickey

# --- Help ---------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@awk 'BEGIN { FS = ":.*##"; printf "op-sign-proxy targets:\n\n" } \
	      /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' \
	      $(MAKEFILE_LIST)
	@echo
	@echo "Paths (override on the command line):"
	@echo "  BINDIR           = $(BINDIR)"
	@echo "  CONFIG_DIR       = $(CONFIG_DIR)"
	@echo "  SYSTEMD_USER_DIR = $(SYSTEMD_USER_DIR)"

.DEFAULT_GOAL := help
