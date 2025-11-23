CARGO_TARGET_DIR ?= target
CARGO_TARGET ?= x86_64-unknown-linux-gnu
PKG_BASE_NAME ?= passless-${CARGO_TARGET}
PROJECT_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' ./Cargo.toml | head -n1)

.DEFAULT: help
.PHONY: help
help:	## Show this help menu.
	@echo "Usage: make [TARGET ...]"
	@echo ""
	@@egrep -h "#[#]" $(MAKEFILE_LIST) | sed -e 's/\\$$//' | awk 'BEGIN {FS = "[:=].*?#[#] "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
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
	cargo test

.PHONY: test-e2e
test-e2e:	## run E2E tests (automatically manages authenticator)
	cargo test --test e2e_webauthn -- --test-threads=1 --ignored

.PHONY: test-e2e-local
test-e2e-local:	## run E2E tests for local backend only
	cargo test --test e2e_webauthn local -- --test-threads=1 --ignored

.PHONY: test-e2e-pass
test-e2e-pass:	## run E2E tests for password-store backend only
	cargo test --test e2e_webauthn pass -- --test-threads=1 --ignored

.PHONY: test-e2e-tpm
test-e2e-tpm:	## run E2E tests for TPM backend only (requires swtpm)
	cargo test --test e2e_webauthn tpm -- --test-threads=1 --ignored

.PHONY: update-changelog
update-changelog:	## automatically update changelog based on commits
	git cliff -t v$(PROJECT_VERSION) -u -p CHANGELOG.md

.PHONY: release
release:	## generate vendor.tar.gz, $(PKG_BASE_NAME).tar.gz, and completions
	cargo vendor
	tar -czf vendor.tar.gz vendor
	cargo build --frozen --release --all-features --target ${CARGO_TARGET}
	tar -czf $(PKG_BASE_NAME).tar.gz -C $(CARGO_TARGET_DIR)/$(CARGO_TARGET)/release passless
	@# Create completions tarball
	@COMPLETION_DIR=$$(find $(CARGO_TARGET_DIR)/$(CARGO_TARGET)/release/build/passless-rs-*/out/completions -type d 2>/dev/null | head -1); \
	if [ -n "$$COMPLETION_DIR" ]; then \
		mkdir -p completions-tmp; \
		cp "$$COMPLETION_DIR"/* completions-tmp/ 2>/dev/null || true; \
		tar -czf passless-completions-$(PROJECT_VERSION).tar.gz -C completions-tmp .; \
		rm -rf completions-tmp; \
		echo "Created completions tarball: passless-completions-$(PROJECT_VERSION).tar.gz"; \
	else \
		echo "Warning: Completions directory not found"; \
	fi
	@echo Released in $(CARGO_TARGET_DIR)/$(CARGO_TARGET)/release/passless

.PHONY: publish
publish:	## publish crate
	cargo publish

# Installation targets
.PHONY: install-binary
install-binary:	## install passless binary to ~/.cargo/bin
	cargo install --path .

.PHONY: install
install: install-binary install-sysusers install-udev install-systemd	## install everything (binary, sysusers, udev, systemd)
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

.PHONY: uninstall-binary
uninstall-binary:	## uninstall passless binary (requires cargo)
	cargo uninstall passless

.PHONY: uninstall
uninstall: uninstall-systemd uninstall-udev uninstall-sysusers uninstall-binary	## uninstall everything (systemd, udev, sysusers, binary)
	@bash -c '. .ci/passless.install && post_remove'
	@echo "    Note: The 'fido' group still exists. To remove it:"
	@echo "      sudo groupdel fido"
	@echo ""
