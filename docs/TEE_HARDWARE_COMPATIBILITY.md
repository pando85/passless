# TEE Hardware Compatibility Analysis

This document analyzes the compatibility of Trusted Execution Environment (TEE) solutions with Intel Core processors released after 2021, addressing the concerns raised in issue #168.

## Executive Summary

**Critical Finding**: Intel SGX was deprecated starting from 11th generation Intel Core processors (2021 onwards), which significantly impacts the viability of SGX-based TEE solutions for modern consumer hardware.

### TL;DR

| Solution | Works on Post-2021 Intel Core? | Status |
|----------|-------------------------------|--------|
| **Gramine (SGX)** | ❌ NO (11th gen+) | Deprecated on consumer CPUs |
| **Occlum (SGX)** | ❌ NO (11th gen+) | Deprecated on consumer CPUs |
| **Enarx** | ⚠️ LIMITED | Requires WebAssembly, hardware support varies |
| **AMD SEV** | ✅ YES | Available on AMD EPYC, not consumer CPUs |
| **Intel TDX** | ✅ YES | Available on 5th Gen Xeon Scalable (2023+) |

## Intel SGX Deprecation Timeline

### Affected Processors (SGX Removed)

Intel deprecated SGX on **client platforms** starting with:

- **11th Generation Intel Core** (Rocket Lake, Tiger Lake) - 2021
- **12th Generation Intel Core** (Alder Lake) - 2021
- **13th Generation Intel Core** (Raptor Lake) - 2022
- **14th Generation Intel Core** (Meteor Lake) - 2023
- **Intel Core Ultra** (200 series) - 2024+

### Still Supported (Server/Enterprise)

Intel SGX remains available on:
- **Intel Xeon Scalable processors** (3rd Gen and newer)
- **Intel Xeon E-series** (select models)

### Why SGX Was Deprecated

Intel's pivot away from SGX on consumer processors was driven by:
1. **Multiple security vulnerabilities** (Foreshadow, Plundervolt, LVI, SGAxe, ÆPIC leak)
2. **Limited adoption** in consumer applications
3. **Shift to cloud/enterprise focus** for confidential computing
4. **Development of newer technologies** (Intel TDX)

## Detailed Solution Analysis

### 1. Gramine (SGX-based)

**Status**: ❌ Not viable for post-2021 Intel Core processors

**Details**:
- Gramine is actively maintained (latest meeting notes: July 2026)
- Requires Intel SGX hardware support
- **Cannot run on 11th gen+ Intel Core processors**
- Still viable for:
  - Older Intel Core processors (10th gen and earlier)
  - Intel Xeon server processors
  - Cloud environments with SGX-enabled instances

**User Experience Impact**:
- Users with modern Intel Core CPUs (2021+) cannot use Gramine
- Requires specific hardware that is increasingly rare in consumer market
- Cloud deployment possible but adds complexity

**Recommendation**: **NOT RECOMMENDED** for Passless due to hardware incompatibility with modern consumer processors.

### 2. Occlum (SGX-based)

**Status**: ❌ Not viable for post-2021 Intel Core processors

**Details**:
- Rust-based library OS for SGX enclaves
- Same hardware limitations as Gramine
- **Cannot run on 11th gen+ Intel Core processors**
- Active development but limited to SGX-capable hardware

**User Experience Impact**:
- Same limitations as Gramine
- Requires older or server-grade hardware
- No path forward for users with modern consumer CPUs

**Recommendation**: **NOT RECOMMENDED** for Passless due to hardware incompatibility.

### 3. Enarx (WebAssembly-based)

**Status**: ⚠️ Limited viability

**Details**:
- Hardware-architecture independent design
- Uses WebAssembly runtime
- Supports multiple TEE backends:
  - Intel SGX (where available)
  - AMD SEV (server processors)
  - Intel TDX (newer Xeon processors)
- **No releases since 2023** - project appears inactive

**User Experience Impact**:
- Theoretical hardware compatibility through WebAssembly
- Requires WebAssembly compilation of Passless
- Limited backend support on consumer hardware
- Uncertain project future

**Recommendation**: **NOT RECOMMENDED** due to project inactivity and WebAssembly overhead.

### 4. AMD SEV (Secure Encrypted Virtualization)

**Status**: ✅ Available but not on consumer hardware

**Details**:
- Available on AMD EPYC server processors (Naples, Rome, Milan, Genoa)
- Provides memory encryption for virtual machines
- **Not available on AMD Ryzen consumer processors**
- Requires server-grade hardware

**User Experience Impact**:
- Not applicable to typical Passless users
- Server/cloud deployment only
- Requires AMD EPYC hardware

**Recommendation**: **NOT APPLICABLE** for consumer-focused Passless deployment.

### 5. Intel TDX (Trust Domain Extensions)

**Status**: ✅ Available but not on consumer hardware

**Details**:
- Successor to SGX for cloud/enterprise workloads
- Available on 5th Gen Intel Xeon Scalable processors (2023+)
- Provides VM-level confidential computing
- **Not available on Intel Core consumer processors**
- Cloud providers offering TDX instances (Azure, AWS, GCP)

**User Experience Impact**:
- Not applicable to local Passless deployment
- Cloud deployment possible
- Requires specific server hardware or cloud instances

**Recommendation**: **NOT APPLICABLE** for local consumer deployment, but viable for cloud scenarios.

## Alternative Approaches

Given the hardware limitations, consider these alternatives:

### 1. Software-Based Security (Current Approach)

**Status**: ✅ Already implemented in Passless

**Details**:
- TPM 2.0 backend provides hardware-backed key storage
- Memory locking (mlockall) prevents swapping
- Core dump prevention
- No new privileges flag

**Advantages**:
- Works on all modern hardware
- No special CPU requirements
- TPM 2.0 widely available since 2016
- Minimal user experience impact

**Recommendation**: **KEEP AND ENHANCE** - This is the most practical approach.

### 2. Enhanced TPM Integration

**Potential Improvements**:
- Use TPM for more than just credential storage
- Implement TPM-based attestation
- Leverage TPM's RNG for cryptographic operations
- Platform Configuration Registers (PCRs) for boot integrity

**Advantages**:
- Available on all modern systems
- No special hardware requirements beyond standard TPM
- Works with post-2021 Intel Core processors

### 3. Hybrid Approach: TPM + Optional TEE

**Strategy**:
- Keep TPM as primary security mechanism (works everywhere)
- Add optional TEE backend for users with compatible hardware
- Detect hardware capabilities at runtime
- Gracefully fall back to TPM-only mode

**Implementation**:
```rust
enum SecurityBackend {
    Tpm,                    // Default, works everywhere
    Tdx,                    // Intel TDX (cloud/server)
    Sev,                    // AMD SEV (server)
    Sgx,                    // Legacy SGX (pre-2021 hardware)
}

fn detect_best_backend() -> SecurityBackend {
    if has_intel_tdx() {
        SecurityBackend::Tdx
    } else if has_amd_sev() {
        SecurityBackend::Sev
    } else if has_intel_sgx() {
        SecurityBackend::Sgx
    } else {
        SecurityBackend::Tpm
    }
}
```

## Recommendations for Passless

### Primary Recommendation

**Continue with TPM 2.0 backend as the primary security mechanism.**

**Rationale**:
1. ✅ Works on all modern hardware (including post-2021 Intel Core)
2. ✅ No special CPU requirements
3. ✅ Already implemented and tested
4. ✅ Minimal user experience impact
5. ✅ Hardware-backed security without TEE complexity

### Secondary Recommendation

**Do NOT implement SGX-based TEE solutions (Gramine, Occlum).**

**Rationale**:
1. ❌ Incompatible with modern consumer processors
2. ❌ Requires users to have older or server-grade hardware
3. ❌ Significant user experience degradation
4. ❌ Limited security benefit over TPM for this use case
5. ❌ Adds complexity without broad benefit

### Future Considerations

**Monitor Intel TDX adoption**:
- If Intel brings TDX to consumer Core processors, reconsider
- Cloud deployment scenarios may benefit from TDX
- Keep architecture flexible for future TEE integration

**Enhance TPM capabilities**:
- Implement TPM-based attestation
- Use TPM for secure boot verification
- Leverage TPM's cryptographic capabilities more extensively

## Hardware Compatibility Matrix

| Processor Generation | Release Year | SGX Support | TDX Support | Recommended Backend |
|---------------------|--------------|-------------|-------------|-------------------|
| Intel Core 10th gen | 2020 | ✅ Yes | ❌ No | TPM or SGX |
| Intel Core 11th gen | 2021 | ❌ No | ❌ No | TPM only |
| Intel Core 12th gen | 2021 | ❌ No | ❌ No | TPM only |
| Intel Core 13th gen | 2022 | ❌ No | ❌ No | TPM only |
| Intel Core 14th gen | 2023 | ❌ No | ❌ No | TPM only |
| Intel Core Ultra | 2024+ | ❌ No | ❌ No | TPM only |
| Intel Xeon 3rd gen | 2020 | ✅ Yes | ❌ No | TPM or SGX |
| Intel Xeon 4th gen | 2022 | ✅ Yes | ❌ No | TPM or SGX |
| Intel Xeon 5th gen | 2023+ | ✅ Yes | ✅ Yes | TPM, SGX, or TDX |
| AMD Ryzen | All | ❌ No | ❌ No | TPM only |
| AMD EPYC | All | ❌ No | ❌ No | TPM or SEV |

## Conclusion

The deprecation of Intel SGX on consumer processors after 2021 makes SGX-based TEE solutions (Gramine, Occlum) **impractical for Passless**. The existing TPM 2.0 backend provides strong security guarantees without hardware compatibility issues.

**Final Recommendation**: Stick with TPM 2.0 as the primary security mechanism. It provides hardware-backed security, works on all modern hardware, and maintains the best user experience. Do not pursue SGX-based TEE solutions for this project.

## References

- [Intel SGX Wikipedia](https://en.wikipedia.org/wiki/Software_Guard_Extensions)
- [Intel SGX Deprecation Announcement](https://www.bleepingcomputer.com/news/security/new-intel-chips-wont-play-blu-ray-disks-due-to-sgx-deprecation/)
- [Gramine Project](https://gramineproject.io/)
- [Enarx Project](https://enarx.dev/)
- [Occlum Project](https://occlum.io/)
- [Intel TDX Overview](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [AMD SEV Overview](https://www.amd.com/en/products/processors/server/epyc/secure-memory-encryption.html)
