CARGO_TARGET_DIR ?= target
CARGO_TARGET ?= x86_64-unknown-linux-gnu
PKG_BASE_NAME ?= passless-${CARGO_TARGET}
PROJECT_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' ./Cargo.toml | head -n1)
AGENT_FUZZ_SMOKE_SECS ?= 10

.DEFAULT: help
.PHONY: help
help:	## Show this help menu.
	@echo "Usage: make [TARGET ...]"
	@echo ""
	@grep -Eh "#[#]" $(MAKEFILE_LIST) | sed -e 's/\\$$//' | awk 'BEGIN {FS = "[:=].*?#[#] "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

.PHONY: build
build:	## compile passless
build:
	cargo build --release

# Pre-commit targets
.PHONY: pre-commit-install
pre-commit-install: ## install pre-commit hooks
	pre-commit install
	pre-commit install --hook-type commit-msg

.PHONY: pre-commit
pre-commit: ## run pre-commit on all files
	pre-commit run --all-files

# Rust formatting and linting targets
.PHONY: fmt
fmt: ## format Rust code using cargo fmt
	cargo fmt

.PHONY: fmt-check
fmt-check: ## check Rust code formatting
	cargo fmt -- --check

.PHONY: clippy
clippy: ## run clippy linter on Rust code
	cargo clippy --all-targets --all-features -- -D warnings

.PHONY: clippy-fix
clippy-fix: ## run clippy with automatic fixes
	cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings

.PHONY: lint
lint: fmt-check clippy ## run all linting checks (fmt + clippy)

.PHONY: lint-fix
lint-fix: fmt clippy-fix ## run all linting with automatic fixes

.PHONY: test
test:	## run tests
test: lint
	cargo test --all-features

.PHONY: test-e2e
test-e2e:	## run E2E tests (automatically manages authenticator)
	cargo test --all-features -- --test-threads=1 --ignored

.PHONY: test-e2e-local
test-e2e-local:	## run E2E tests for local backend only
	cargo test --all-features --test e2e_webauthn test_local_ -- --test-threads=1 --ignored

.PHONY: test-e2e-pass
test-e2e-pass:	## run E2E tests for password-store backend only
	cargo test --all-features --test e2e_webauthn test_pass_ -- --test-threads=1 --ignored
.PHONY: test-e2e-tpm
test-e2e-tpm:	## run E2E tests for TPM backend only (requires swtpm)
	cargo test --all-features --test e2e_webauthn test_tpm_ -- --test-threads=1 --ignored

.PHONY: test-agent-validation
test-agent-validation:	## run deterministic agent validation (no privileged or live browser changes)
	tools/agent-validation/test-deterministic.sh

.PHONY: test-agent-fuzz-smoke
test-agent-fuzz-smoke:	## run bounded agent protocol fuzz smoke tests (requires cargo-fuzz + nightly)
	cargo +nightly fuzz run agent_protocol_decode -- -max_total_time=$(AGENT_FUZZ_SMOKE_SECS) -max_len=20000
	cargo +nightly fuzz run agent_request_validation -- -max_total_time=$(AGENT_FUZZ_SMOKE_SECS) -max_len=20000

.PHONY: update-changelog
update-changelog:	## automatically update changelog based on commits
	git cliff -t v$(PROJECT_VERSION) -u -p CHANGELOG.md

.PHONY: release
release:	## generate vendor.tar.gz, $(PKG_BASE_NAME).tar.gz, and completions
	cargo vendor
	tar -czf vendor.tar.gz vendor
	cargo build --frozen --release --all-features --target ${CARGO_TARGET}
	tar -czf $(PKG_BASE_NAME).tar.gz -C $(CARGO_TARGET_DIR)/$(CARGO_TARGET)/release passless passless-git-sync sign-proxy agent-prompt-probe
	@# Create completions tarball
	@COMPLETION_DIR=$$(find $(CARGO_TARGET_DIR)/$(CARGO_TARGET)/release/build/passless-*/out/completions -type d 2>/dev/null | head -1); \
	if [ -n "$$COMPLETION_DIR" ]; then \
		mkdir -p completions-tmp; \
		cp "$$COMPLETION_DIR"/* completions-tmp/ 2>/dev/null || true; \
		tar -czf passless-completions-$(PROJECT_VERSION).tar.gz -C completions-tmp .; \
		rm -rf completions-tmp; \
		echo "Created completions tarball: passless-completions-$(PROJECT_VERSION).tar.gz"; \
	else \
		echo "Warning: Completions directory not found"; \
	fi
	@echo Released binaries in $(CARGO_TARGET_DIR)/$(CARGO_TARGET)/release/: passless, passless-git-sync, sign-proxy, agent-prompt-probe

.PHONY: update-version
update-version: ## update version from VERSION file in all Cargo.toml manifests
update-version: */Cargo.toml
	@VERSION=$$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1); \
	sed -i -E "s/(passless-[a-z0-9-]+ = \{ path = \"[^\"]+\", version = )\"[^\"]+\"/\1\"$$VERSION\"/g" Cargo.toml && \
	cargo update --workspace ; \
	echo updated to version "$$VERSION" cargo files ; \

.PHONY: publish
publish:	## publish crate
	cargo publish --workspace

# Installation targets
.PHONY: install-binary
install-binary:	## install passless binary to ~/.cargo/bin
	cargo install --path cmd/passless --features agent

.PHONY: install
install: install-binary install-sysusers install-udev install-systemd install-modules	## install everything (binary, sysusers, udev, systemd)
	@bash -c '. .ci/passless.install && post_install'

.PHONY: install-systemd
install-systemd:	## install systemd user service
	@mkdir -p ~/.config/systemd/user
	@cp contrib/systemd/passless.service ~/.config/systemd/user/
	@systemctl --user daemon-reload
	@echo "Systemd service installed."

.PHONY: uninstall-systemd
uninstall-systemd:	## uninstall systemd user service
	@systemctl --user stop passless.service 2>/dev/null || true
	@systemctl --user disable passless.service 2>/dev/null || true
	@rm -f ~/.config/systemd/user/passless.service
	@systemctl --user daemon-reload
	@echo "Systemd service uninstalled."

.PHONY: install-udev
install-udev:	## install udev rules (requires sudo)
	@echo "Installing udev rules (requires sudo)..."
	@sudo cp contrib/udev/90-passless.rules /etc/udev/rules.d/
	@sudo udevadm control --reload-rules
	@sudo udevadm trigger
	@echo "Udev rules installed."

.PHONY: uninstall-udev
uninstall-udev:	## uninstall udev rules (requires sudo)
	@echo "Removing udev rules (requires sudo)..."
	@sudo rm -f /etc/udev/rules.d/90-passless.rules
	@sudo udevadm control --reload-rules
	@sudo udevadm trigger
	@echo "Udev rules removed."

.PHONY: install-sysusers
install-sysusers:	## install sysusers configuration (requires sudo)
	@echo "Installing sysusers configuration (requires sudo)..."
	@sudo cp contrib/sysusers.d/passless.conf /usr/lib/sysusers.d/
	@sudo systemd-sysusers
	@echo "Sysusers configuration installed. The 'fido' group has been created."

.PHONY: uninstall-sysusers
uninstall-sysusers:	## uninstall sysusers configuration (requires sudo)
	@echo "Removing sysusers configuration (requires sudo)..."
	@sudo rm -f /usr/lib/sysusers.d/passless.conf
	@echo "Sysusers configuration removed."
	@echo "Note: The 'fido' group still exists and must be removed manually if desired."

.PHONY: install-modules
install-modules:	## install modules-load configuration (requires sudo)
	@echo "Installing modules-load configuration (requires sudo)..."
	@sudo cp contrib/modules-load.d/fido.conf /etc/modules-load.d/
	@echo "Modules-load configuration installed."

.PHONY: uninstall-modules
uninstall-modules:	## uninstall modules-load configuration (requires sudo)
	@echo "Removing modules-load configuration (requires sudo)..."
	@sudo rm -f /etc/modules-load.d/fido.conf
	@echo "Modules-load configuration removed."

.PHONY: uninstall-binary
uninstall-binary:	## uninstall passless binary (requires cargo)
	cargo uninstall passless

.PHONY: uninstall
uninstall: uninstall-systemd uninstall-udev uninstall-sysusers uninstall-binary uninstall-modules	## uninstall everything (systemd, udev, sysusers, binary)
	@bash -c '. .ci/passless.install && post_remove'
	@echo "    Note: The 'fido' group still exists. To remove it:"
	@echo "      sudo groupdel fido"
	@echo ""

.PHONY: check-doc-links
check-doc-links: ## check internal markdown links in docs/
	@tools/check-doc-links.sh
