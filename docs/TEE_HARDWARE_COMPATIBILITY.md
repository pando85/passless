# TEE Hardware Compatibility Analysis

This document analyzes the compatibility of Trusted Execution Environment (TEE) solutions with
Intel Core processors released after 2021, addressing the concerns raised in issue #168.

## Summary

Intel SGX was deprecated starting from 11th generation Intel Core processors (2021 onwards), which
significantly impacts the viability of SGX-based TEE solutions for modern consumer hardware.

### Compatibility Overview

| Solution | Post-2021 Intel Core | Status |
|----------|---------------------|--------|
| **Gramine (SGX)** | No (11th gen+) | Deprecated on consumer CPUs |
| **Occlum (SGX)** | No (11th gen+) | Deprecated on consumer CPUs |
| **Enarx** | Limited | Requires WebAssembly; hardware support varies |
| **AMD SEV** | Yes | Available on AMD EPYC, not consumer CPUs |
| **Intel TDX** | Yes | Available on 5th Gen Xeon Scalable (2023+) |

## Intel SGX Deprecation Timeline

### Affected Processors (SGX Removed)

Intel deprecated SGX on client platforms starting with:

- **11th Generation Intel Core** (Rocket Lake, Tiger Lake) — 2021
- **12th Generation Intel Core** (Alder Lake) — 2021
- **13th Generation Intel Core** (Raptor Lake) — 2022
- **14th Generation Intel Core** (Meteor Lake) — 2023
- **Intel Core Ultra** (200 series) — 2024+

### Still Supported (Server/Enterprise)

Intel SGX remains available on:

- **Intel Xeon Scalable processors** (3rd Gen and newer)
- **Intel Xeon E-series** (select models)

### Reasons for Deprecation

Intel's pivot away from SGX on consumer processors was driven by:

1. Multiple security vulnerabilities (Foreshadow, Plundervolt, LVI, SGAxe, AEPI leak)
2. Limited adoption in consumer applications
3. Shift to cloud/enterprise focus for confidential computing
4. Development of newer technologies (Intel TDX)

## Detailed Solution Analysis

### 1. Gramine (SGX-based)

**Status: Not viable for post-2021 Intel Core processors**

Gramine is actively maintained and requires Intel SGX hardware support. It cannot run on 11th gen+
Intel Core processors. It remains viable for older Intel Core processors (10th gen and earlier),
Intel Xeon server processors, and cloud environments with SGX-enabled instances.

Users with modern Intel Core CPUs (2021+) cannot use Gramine. The required hardware is increasingly
rare in the consumer market. Cloud deployment is possible but adds complexity.

**Recommendation:** Not recommended for Passless due to hardware incompatibility with modern
consumer processors.

### 2. Occlum (SGX-based)

**Status: Not viable for post-2021 Intel Core processors**

Occlum is a Rust-based library OS for SGX enclaves. It shares the same hardware limitations as
Gramine and cannot run on 11th gen+ Intel Core processors. Despite active development, it is
limited to SGX-capable hardware.

**Recommendation:** Not recommended for Passless due to hardware incompatibility.

### 3. Enarx (WebAssembly-based)

**Status: Limited viability**

Enarx has a hardware-architecture independent design using a WebAssembly runtime. It supports
multiple TEE backends: Intel SGX (where available), AMD SEV (server processors), and Intel TDX
(newer Xeon processors). However, the project has had no releases since 2023 and appears inactive.

The theoretical hardware compatibility through WebAssembly requires WebAssembly compilation of
Passless, offers limited backend support on consumer hardware, and has an uncertain project future.

**Recommendation:** Not recommended due to project inactivity and WebAssembly overhead.

### 4. AMD SEV (Secure Encrypted Virtualization)

**Status: Available but not on consumer hardware**

AMD SEV is available on AMD EPYC server processors (Naples, Rome, Milan, Genoa) and provides memory
encryption for virtual machines. It is not available on AMD Ryzen consumer processors and requires
server-grade hardware.

**Recommendation:** Not applicable for consumer-focused Passless deployment.

### 5. Intel TDX (Trust Domain Extensions)

**Status: Available but not on consumer hardware**

Intel TDX is the successor to SGX for cloud/enterprise workloads, available on 5th Gen Intel Xeon
Scalable processors (2023+). It provides VM-level confidential computing but is not available on
Intel Core consumer processors. Cloud providers offering TDX instances include Azure, AWS, and GCP.

**Recommendation:** Not applicable for local consumer deployment, but viable for cloud scenarios.

## Alternative Approaches

Given the hardware limitations, the following alternatives are available:

### 1. Software-Based Security (Current Approach)

**Status: Already implemented in Passless**

- TPM 2.0 backend provides hardware-backed key storage
- Memory locking (`mlockall`) prevents swapping
- Core dump prevention
- No new privileges flag
- [Portable TPM backend](TPM_PORTABLE.md) (experimental): TPM-resident, non-exportable
  signing keys synchronized across devices via a recovery seed. Validated against swtpm;
  cross-vendor hardware TPM testing is pending (see
  [interoperability matrix](TPM_PORTABLE.md#interoperability-matrix)).

This approach works on all modern hardware with no special CPU requirements. TPM 2.0 has been
widely available since 2016 and has minimal user experience impact.

**Recommendation:** Keep and enhance — this is the most practical approach.

### 2. Enhanced TPM Integration

Potential improvements include using the TPM for more than just credential storage, implementing
TPM-based attestation, leveraging the TPM's RNG for cryptographic operations, and using Platform
Configuration Registers (PCRs) for boot integrity.

The [Portable TPM backend](TPM_PORTABLE.md) already provides TPM-resident signing keys portable
across devices provisioned from the same recovery seed (experimental, ES256 only).

## Recommendations

### Primary: Continue with TPM 2.0

The TPM 2.0 backend should remain the primary security mechanism because it:

1. Works on all modern hardware, including post-2021 Intel Core processors
2. Has no special CPU requirements
3. Is already implemented and tested
4. Has minimal user experience impact
5. Provides hardware-backed security without TEE complexity

### Secondary: Do Not Implement SGX-based TEE Solutions

SGX-based solutions (Gramine, Occlum) should not be pursued because they:

1. Are incompatible with modern consumer processors
2. Require users to have older or server-grade hardware
3. Cause significant user experience degradation
4. Offer limited security benefit over TPM for this use case
5. Add complexity without broad benefit

### Future Considerations

- **Monitor Intel TDX adoption:** If Intel brings TDX to consumer Core processors, reconsider.
  Cloud deployment scenarios may benefit from TDX. Keep the architecture flexible for future TEE
  integration.
- **Enhance TPM capabilities:** Implement TPM-based attestation, use TPM for secure boot
  verification, and leverage TPM cryptographic capabilities more extensively.

## Hardware Compatibility Matrix

| Processor Generation | Release Year | SGX | TDX | Recommended Backend |
|---------------------|--------------|-----|-----|-------------------|
| Intel Core 10th gen | 2020 | Yes | No | TPM or SGX |
| Intel Core 11th gen | 2021 | No | No | TPM only |
| Intel Core 12th gen | 2021 | No | No | TPM only |
| Intel Core 13th gen | 2022 | No | No | TPM only |
| Intel Core 14th gen | 2023 | No | No | TPM only |
| Intel Core Ultra | 2024+ | No | No | TPM only |
| Intel Xeon 3rd gen | 2020 | Yes | No | TPM or SGX |
| Intel Xeon 4th gen | 2022 | Yes | No | TPM or SGX |
| Intel Xeon 5th gen | 2023+ | Yes | Yes | TPM, SGX, or TDX |
| AMD Ryzen | All | No | No | TPM only |
| AMD EPYC | All | No | No | TPM or SEV |

## Conclusion

The deprecation of Intel SGX on consumer processors after 2021 makes SGX-based TEE solutions
(Gramine, Occlum) impractical for Passless. The existing TPM 2.0 backend provides strong security
guarantees without hardware compatibility issues and should remain the primary security mechanism.

## References

- [Intel SGX — Wikipedia](https://en.wikipedia.org/wiki/Software_Guard_Extensions)
- [Intel SGX Deprecation — BleepingComputer](https://www.bleepingcomputer.com/news/security/new-intel-chips-wont-play-blu-ray-disks-due-to-sgx-deprecation/)
- [Gramine Project](https://gramineproject.io/)
- [Enarx Project](https://enarx.dev/)
- [Occlum Project](https://occlum.io/)
- [Intel TDX Overview](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [AMD SEV Overview](https://www.amd.com/en/products/processors/server/epyc/secure-memory-encryption.html)
