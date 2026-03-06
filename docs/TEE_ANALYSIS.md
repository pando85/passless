# TEE (Trusted Execution Environment) Analysis for Passless

**Issue:** #168
**Date:** 2026-03-06
**Status:** Analysis Complete

## Executive Summary

This document analyzes Trusted Execution Environment (TEE) solutions for securing the Passless FIDO2 authenticator. The goal is to improve security while maintaining the same user experience.

### Recommendation

**Primary Recommendation: Gramine with Intel SGX**

Gramine is the most suitable TEE solution for Passless due to:
- Production-ready with active development (latest release: June 2025)
- Runs unmodified Linux binaries (no code changes required)
- Minimal user experience impact
- Strong industry backing (Intel, Golem, Invisible Things Lab)
- Part of Confidential Computing Consortium

**Secondary Recommendation: Keep TPM 2.0 Backend**

The existing TPM backend should remain as it provides hardware binding without requiring TEE-capable hardware. TEE support should be an optional enhancement for users with Intel SGX-capable hardware.

---

## 1. TEE Solutions Overview

### 1.1 Enarx

| Aspect | Details |
|--------|---------|
| **Status** | Active development, but no releases since January 2023 |
| **Last Commit** | September 2025 |
| **Technology** | WebAssembly-based runtime for TEEs |
| **Supported Hardware** | Intel SGX, AMD SEV |
| **Architecture** | Requires compilation to WebAssembly |

**Pros:**
- Hardware-agnostic approach
- Part of Confidential Computing Consortium
- Supports both Intel SGX and AMD SEV

**Cons:**
- No stable release in 3+ years
- Requires WebAssembly compilation
- WebAssembly limitations for system calls (UHID access)
- Uncertain project trajectory

**Feasibility for Passless: LOW**

The WebAssembly approach presents significant challenges:
- UHID device access requires Linux system calls not typically available in WASM
- Would require significant architecture changes
- Project appears to be in maintenance mode

---

### 1.2 Gramine (formerly Graphene)

| Aspect | Details |
|--------|---------|
| **Status** | Active development, stable releases |
| **Last Release** | June 2025 |
| **Technology** | Library OS for unmodified applications |
| **Supported Hardware** | Intel SGX |
| **Architecture** | Runs native Linux binaries in SGX enclaves |

**Pros:**
- Runs unmodified applications (no code changes)
- Docker container support (Gramine Shielded Containers)
- Production-ready with commercial deployments
- Active community and documentation
- Supports Rust applications natively

**Cons:**
- Intel SGX only (no AMD SEV support)
- Requires SGX-capable hardware
- Manifest file configuration required
- Performance overhead (~10-30%)

**Feasibility for Passless: HIGH**

Gramine can run Passless with minimal modifications:
1. Create a manifest file for Passless
2. Package with Gramine Shielded Containers
3. No source code changes required

**Implementation Path:**
```bash
# Example manifest structure
gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu passless.manifest.template passless.manifest
gramine-sgx-sign --key enclave-key.pem --manifest passless.manifest --output passless.manifest.sgx
gramine-sgx passless
```

---

### 1.3 Occlum

| Aspect | Details |
|--------|---------|
| **Status** | Active development |
| **Last Release** | 2024 (regular releases) |
| **Technology** | LibOS for Intel SGX |
| **Supported Hardware** | Intel SGX |
| **Architecture** | Memory-safe LibOS written in Rust |

**Pros:**
- Written in Rust (memory-safe LibOS)
- Supports multi-process applications
- Good documentation
- Designed for production use

**Cons:**
- Intel SGX only
- Requires application linking against Occlum
- Less mature than Gramine
- Docker integration less straightforward

**Feasibility for Passless: MEDIUM**

Occlum is viable but requires more integration work than Gramine:
- Application needs to be linked with Occlum toolchain
- May require modifications for UHID access patterns

---

### 1.4 Confidential Containers (CNCF)

| Aspect | Details |
|--------|---------|
| **Status** | CNCF Sandbox project, active |
| **Releases** | Every 8 weeks |
| **Technology** | Kubernetes/container-focused |
| **Supported Hardware** | Intel SGX, AMD SEV, IBM SE |

**Pros:**
- Kubernetes-native
- Multi-platform TEE support
- Strong CNCF community
- Regular releases

**Cons:**
- Kubernetes/container orchestration required
- Overkill for single-node authenticator
- Designed for cloud deployments

**Feasibility for Passless: LOW**

Confidential Containers is designed for cloud Kubernetes deployments, not single-node authenticator use cases. It would add significant complexity without proportional security benefit.

---

### 1.5 Intel SGX SDK (Direct Integration)

| Aspect | Details |
|--------|---------|
| **Status** | Mature, production-ready |
| **Technology** | Native SGX enclave development |
| **Architecture** | Requires code partitioning |

**Pros:**
- Maximum control and performance
- Native integration
- Industry standard

**Cons:**
- Significant code refactoring required
- Enclave/untrusted boundary complexity
- Development overhead
- Security-critical code review needed

**Feasibility for Passless: LOW**

Direct SGX integration would require:
- Partitioning code into enclave and untrusted components
- Rewriting all I/O operations (UHID, notifications, storage)
- Ongoing security maintenance

---

## 2. Passless Architecture Analysis

### 2.1 Current Security Model

```
┌─────────────────────────────────────────────────────────────┐
│                     User Space (Untrusted)                   │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    Passless Process                      ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ ││
│  │  │ CTAP Handler│  │Credential   │  │  Notification   │ ││
│  │  │             │  │Storage      │  │  (D-Bus)        │ ││
│  │  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘ ││
│  │         │                │                   │          ││
│  │  ┌──────┴──────┐  ┌──────┴──────┐           │          ││
│  │  │  soft-fido2 │  │   TPM/GPG   │           │          ││
│  │  │  (Crypto)   │  │  (Storage)  │           │          ││
│  │  └─────────────┘  └─────────────┘           │          ││
│  └─────────────────────────────────────────────┼──────────┘│
│                           │                    │           │
└───────────────────────────┼────────────────────┼───────────┘
                            │                    │
┌───────────────────────────┼────────────────────┼───────────┐
│                     Kernel Space               │           │
│  ┌──────────────────┐    │          ┌─────────┴─────────┐ │
│  │    UHID Device   │◄───┘          │    D-Bus System   │ │
│  └──────────────────┘               └───────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Security Hardening (Current)

The current implementation includes:
- `mlockall()` - Memory locking to prevent swapping
- Core dump prevention
- Zeroize for sensitive data
- TPM/GPG encryption for credentials at rest

### 2.3 Attack Surface Analysis

| Attack Vector | Current Protection | TEE Improvement |
|--------------|-------------------|-----------------|
| Memory dumping | mlockall (partial) | Full memory encryption |
| Root process inspection | Limited | Complete isolation |
| Kernel compromise | None | Hardware isolation |
| Cold boot attacks | Limited | SGX sealed storage |
| Credential exfiltration | TPM/GPG encryption | Hardware-bound keys |

---

## 3. Proposed Architecture with TEE

### 3.1 Gramine Integration Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                         Untrusted Host                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Gramine Runtime                        │  │
│  │  ┌──────────────────────────────────────────────────────┐│  │
│  │  │                Intel SGX Enclave                      ││  │
│  │  │  ┌────────────────────────────────────────────────┐  ││  │
│  │  │  │              Passless Process                   │  ││  │
│  │  │  │  ┌────────────┐  ┌─────────────┐               │  ││  │
│  │  │  │  │CTAP Handler│  │Credential   │               │  ││  │
│  │  │  │  │(soft-fido2)│  │Storage      │               │  ││  │
│  │  │  │  └────────────┘  └─────────────┘               │  ││  │
│  │  │  │                     │                           │  ││  │
│  │  │  │         Sealed Storage (SGX Protected)          │  ││  │
│  │  │  └────────────────────────────────────────────────┘  ││  │
│  │  └──────────────────────────────────────────────────────┘│  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                    │
│  ┌──────────────────┐      │      ┌───────────────────────┐   │
│  │    UHID Device   │◄─────┘      │ Notification Proxy    │   │
│  └──────────────────┘             └───────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

### 3.2 User Experience Impact

| Aspect | Current | With Gramine | Impact |
|--------|---------|--------------|--------|
| Installation | Package/cargo | Package + manifest | Minimal |
| Performance | Native | ~10-20% overhead | Acceptable |
| Hardware | Any Linux | Intel SGX required | Significant |
| Notifications | Direct | Via proxy | Minor change |
| Storage | TPM/pass/local | Sealed files | Transparent |

---

## 4. Implementation Recommendations

### 4.1 Phase 1: Gramine Support (Recommended)

**Objective:** Add optional Gramine/SGX support for users with compatible hardware.

**Steps:**
1. Create Gramine manifest template for Passless
2. Add GSC (Gramine Shielded Containers) support
3. Implement sealed storage backend for SGX
4. Create notification proxy for enclave communication
5. Document hardware requirements and setup

**Estimated Effort:** 2-4 weeks

**Manifest Template Example:**
```toml
# passless.manifest.template
loader.entrypoint = "file:/usr/bin/passless"
loader.env.LD_LIBRARY_PATH = "/lib/x86_64-linux-gnu"

# UHID device access
fs.mount.lib.type = "chroot"
fs.mount.lib.path = "/lib"
fs.mount.lib.uri = "file:/lib"

# SGX configuration
sgx.enclave_size = "256M"
sgx.thread_num = 4
sgx.remote_attestation = "none"

# Encrypted storage
fs.mount.data.type = "encrypted"
fs.mount.data.path = "/var/lib/passless"
fs.mount.data.uri = "file:/var/lib/passless"
```

### 4.2 Phase 2: Hardware Detection

Add runtime detection for TEE capabilities:

```rust
pub enum TeeBackend {
    None,
    IntelSgx,
    AmdSev,
}

pub fn detect_tee() -> TeeBackend {
    // Check for SGX
    if Path::new("/dev/sgx_enclave").exists() {
        return TeeBackend::IntelSgx;
    }
    // Check for SEV
    if let Ok(content) = fs::read_to_string("/sys/module/kvm_amd/parameters/sev") {
        if content.trim() == "Y" {
            return TeeBackend::AmdSev;
        }
    }
    TeeBackend::None
}
```

### 4.3 Phase 3: Sealed Storage Backend

Implement SGX-sealed storage as a new backend:

```rust
pub struct SgxSealedStorage {
    sealed_dir: PathBuf,
}

impl CredentialStorage for SgxSealedStorage {
    // Credentials sealed with SGX seal key
    // Only accessible within the same enclave
}
```

---

## 5. Hardware Requirements

### 5.1 Intel SGX Requirements

| Requirement | Details |
|-------------|---------|
| CPU | Intel 6th gen+ (Skylake) or newer |
| Feature | SGX2 (EDMM) preferred |
| Memory | EPC (Enclave Page Cache) - typically 128MB-256MB |
| BIOS | SGX enabled in firmware |
| Driver | Linux SGX driver (in-kernel 5.11+) |

### 5.2 Availability

- **Consumer Hardware:** Intel Core i5/i7/i9 6th gen+, Xeon E3/E5/E7 v5+
- **Cloud Instances:**
  - Azure: DC-series, EC-series
  - Google Cloud: Not widely available
  - AWS: Not widely available (AMD SEV preferred)

---

## 6. Alternative: AMD SEV Consideration

AMD SEV (Secure Encrypted Virtualization) encrypts VM memory, providing different guarantees:

| Aspect | Intel SGX | AMD SEV |
|--------|-----------|---------|
| Isolation Unit | Application (enclave) | Entire VM |
| Code Changes | Minimal (with Gramine) | None required |
| Memory Encryption | Enclave-only | Entire VM |
| Attestation | Local/Remote | Remote (SEV-SNP) |
| Availability | Limited cloud support | Broad cloud support |

**Recommendation:** AMD SEV is better suited for cloud deployments. For desktop use, Intel SGX with Gramine is the preferred path.

---

## 7. Risk Assessment

### 7.1 Implementation Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| SGX hardware availability | Medium | High | Keep TPM backend as primary |
| Performance degradation | Low | Medium | Benchmark and optimize |
| Notification proxy complexity | Low | Low | Use simple D-Bus bridge |
| Gramine compatibility issues | Low | Medium | Test thoroughly |

### 7.2 Security Considerations

- SGX has had side-channel vulnerabilities (Spectre, Meltdown, etc.)
- Mitigations exist but require up-to-date microcode
- SGX attestation provides additional assurance
- Sealed storage provides hardware binding

---

## 8. Conclusion

### Summary of Recommendations

1. **Implement Gramine support** as an optional enhancement for users with Intel SGX hardware
2. **Keep TPM backend** as the recommended option for most users
3. **Document hardware requirements** clearly for users interested in TEE protection
4. **Consider cloud deployment** scenarios with AMD SEV in the future

### Priority Order

1. **Low:** Create Gramine manifest and documentation
2. **Low:** Add SGX-sealed storage backend
3. **Future:** Evaluate AMD SEV for cloud deployments
4. **Future:** Consider Confidential Containers for Kubernetes deployments

### Expected Outcome

Users with Intel SGX hardware will have an additional security layer that protects:
- Cryptographic keys in memory
- Credential processing
- Attestation capabilities

The same user experience is preserved through Gramine's transparent execution model.

---

## References

- [Gramine Documentation](https://gramine.readthedocs.io/)
- [Intel SGX Developer Reference](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html)
- [Enarx Project](https://enarx.dev/)
- [Confidential Containers (CNCF)](https://confidentialcontainers.org/)
- [Occlum Project](https://github.com/occlum/occlum)
