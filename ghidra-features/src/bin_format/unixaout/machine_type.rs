//! Unix a.out machine type constants ported from Ghidra's `UnixAoutMachineType.java`.

// Machine ID values for the UNIX a.out format.
//
// Sourced from NetBSD's aout_mids.h and GNU BFD Library's libaout.h.

/// Unknown machine type.
pub const M_UNKNOWN: u8 = 0x00;
/// Motorola 68010.
pub const M_68010: u8 = 0x01;
/// Motorola 68020.
pub const M_68020: u8 = 0x02;
/// SPARC.
pub const M_SPARC: u8 = 0x03;
/// MIPS R3000.
pub const M_R3000: u8 = 0x04;
/// National Semiconductor NS32032.
pub const M_NS32032: u8 = 0x40;
/// National Semiconductor NS32532.
pub const M_NS32532: u8 = 0x45;
/// Intel 386.
pub const M_386: u8 = 0x64;
/// AMD 29000.
pub const M_29K: u8 = 0x65;
/// i386-based Sequent machine running DYNIX.
pub const M_386_DYNIX: u8 = 0x66;
/// ARM.
pub const M_ARM: u8 = 0x67;
/// Sparclet (M_SPARC + 128).
pub const M_SPARCLET: u8 = 0x83;
/// NetBSD/i386.
pub const M_386_NETBSD: u8 = 0x86;
/// NetBSD/m68k, 8K pages.
pub const M_M68K_NETBSD: u8 = 0x87;
/// NetBSD/m68k, 4K pages.
pub const M_M68K4K_NETBSD: u8 = 0x88;
/// NetBSD/ns32k.
pub const M_532_NETBSD: u8 = 0x89;
/// NetBSD/sparc.
pub const M_SPARC_NETBSD: u8 = 0x8a;
/// NetBSD/pmax (MIPS little-endian).
pub const M_PMAX_NETBSD: u8 = 0x8b;
/// NetBSD/VAX (1K pages).
pub const M_VAX_NETBSD: u8 = 0x8c;
/// NetBSD/Alpha.
pub const M_ALPHA_NETBSD: u8 = 0x8d;
/// MIPS big-endian.
pub const M_MIPS: u8 = 0x8e;
/// NetBSD/arm32.
pub const M_ARM6_NETBSD: u8 = 0x8f;
/// SuperH SH-3.
pub const M_SH3: u8 = 0x91;
/// PowerPC 64.
pub const M_POWERPC64: u8 = 0x94;
/// NetBSD/PowerPC (big-endian).
pub const M_POWERPC_NETBSD: u8 = 0x95;
/// NetBSD/VAX (4K pages).
pub const M_VAX4K_NETBSD: u8 = 0x96;
/// MIPS R2000/R3000.
pub const M_MIPS1: u8 = 0x97;
/// MIPS R4000/R6000.
pub const M_MIPS2: u8 = 0x98;
/// OpenBSD/m88k.
pub const M_88K_OPENBSD: u8 = 0x99;
/// OpenBSD/hppa (PA-RISC).
pub const M_HPPA_OPENBSD: u8 = 0x9a;
/// SuperH 64-bit.
pub const M_SH5_64: u8 = 0x9b;
/// NetBSD/sparc64.
pub const M_SPARC64_NETBSD: u8 = 0x9c;
/// NetBSD/amd64.
pub const M_X86_64_NETBSD: u8 = 0x9d;
/// SuperH 32-bit (ILP32).
pub const M_SH5_32: u8 = 0x9e;
/// Intel Itanium (IA-64).
pub const M_IA64: u8 = 0x9f;
/// ARM AARCH64.
pub const M_AARCH64: u8 = 0xb7;
/// OpenRISC 1000.
pub const M_OR1K: u8 = 0xb8;
/// RISC-V.
pub const M_RISCV: u8 = 0xb9;
/// Axis ETRAX CRIS.
pub const M_CRIS: u8 = 0xff;

/// Returns a human-readable name for the given machine type ID.
pub fn machine_type_name(machtype: u8) -> &'static str {
    match machtype {
        M_UNKNOWN => "UNKNOWN",
        M_68010 => "MC68010",
        M_68020 => "MC68020",
        M_SPARC => "SPARC",
        M_R3000 => "R3000",
        M_NS32032 => "NS32032",
        M_NS32532 => "NS32532",
        M_386 => "i386",
        M_29K => "29000",
        M_386_DYNIX => "i386/DYNIX",
        M_ARM => "ARM",
        M_SPARCLET => "Sparclet",
        M_386_NETBSD => "NetBSD/i386",
        M_M68K_NETBSD => "NetBSD/m68k",
        M_M68K4K_NETBSD => "NetBSD/m68k/4K",
        M_532_NETBSD => "NetBSD/ns32k",
        M_SPARC_NETBSD => "NetBSD/sparc",
        M_PMAX_NETBSD => "NetBSD/pmax",
        M_VAX_NETBSD => "NetBSD/VAX",
        M_ALPHA_NETBSD => "NetBSD/Alpha",
        M_MIPS => "MIPS/BE",
        M_ARM6_NETBSD => "NetBSD/arm32",
        M_SH3 => "SH-3",
        M_POWERPC64 => "PowerPC64",
        M_POWERPC_NETBSD => "NetBSD/PowerPC",
        M_VAX4K_NETBSD => "NetBSD/VAX/4K",
        M_MIPS1 => "MIPS1",
        M_MIPS2 => "MIPS2",
        M_88K_OPENBSD => "OpenBSD/m88k",
        M_HPPA_OPENBSD => "OpenBSD/hppa",
        M_SH5_64 => "SH-5/64",
        M_SPARC64_NETBSD => "NetBSD/sparc64",
        M_X86_64_NETBSD => "NetBSD/amd64",
        M_SH5_32 => "SH-5/32",
        M_IA64 => "IA-64",
        M_AARCH64 => "AARCH64",
        M_OR1K => "OpenRISC",
        M_RISCV => "RISC-V",
        M_CRIS => "CRIS",
        _ => "UNKNOWN",
    }
}

/// Returns the Ghidra language specification string for the given machine type,
/// or `None` if the type is unrecognized.
///
/// The language spec has the format `"ARCH:ENDIAN:SIZE:VARIANT"`.
pub fn language_spec_for(machtype: u8, is_le: bool) -> Option<(&'static str, &'static str)> {
    let endian = if is_le { "LE" } else { "BE" };
    match machtype {
        M_68010 => Some(("68000:BE:32:MC68010", "default")),
        M_68020 => Some(("68000:BE:32:MC68020", "default")),
        M_M68K_NETBSD | M_M68K4K_NETBSD => Some(("68000:BE:32:default", "default")),
        M_SPARC | M_SPARCLET => Some(("sparc:BE:32:default", "default")),
        M_SPARC_NETBSD | M_SPARC64_NETBSD => Some(("sparc:BE:64:default", "default")),
        M_PMAX_NETBSD | M_MIPS1 | M_MIPS2 | M_R3000 => Some(("MIPS:LE:32:default", "default")),
        M_MIPS => Some(("MIPS:BE:32:default", "default")),
        M_532_NETBSD | M_NS32032 | M_NS32532 => Some(("UNKNOWN:LE:32:default", "default")),
        M_386 | M_386_DYNIX | M_386_NETBSD => Some(("x86:LE:32:default", "gcc")),
        M_X86_64_NETBSD => Some(("x86:LE:64:default", "gcc")),
        M_ARM | M_ARM6_NETBSD => Some(("ARM:BE:32:default", "default")),
        M_AARCH64 => Some(("AARCH64:BE:64:default", "default")),
        M_OR1K => Some(("UNKNOWN:BE:32:default", "default")),
        M_RISCV => Some(("RISCV:LE:32:default", "default")),
        M_HPPA_OPENBSD => Some(("pa-risc:BE:32:default", "default")),
        M_POWERPC_NETBSD => Some(("PowerPC:BE:32:default", "default")),
        M_POWERPC64 => Some(("PowerPC:BE:64:default", "default")),
        M_SH3 | M_SH5_32 => Some(("SuperH:BE:32:default", "default")),
        M_SH5_64 => Some(("SuperH:BE:64:default", "default")),
        M_VAX_NETBSD | M_VAX4K_NETBSD => Some(("UNKNOWN:LE:32:default", "default")),
        M_CRIS => Some(("UNKNOWN:LE:32:default", "default")),
        M_ALPHA_NETBSD | M_IA64 => Some(("UNKNOWN:BE:64:default", "default")),
        M_29K | M_88K_OPENBSD => Some(("UNKNOWN:BE:32:default", "default")),
        M_UNKNOWN => Some(("UNKNOWN:BE:32:default", "default")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_type_names() {
        assert_eq!(machine_type_name(M_386), "i386");
        assert_eq!(machine_type_name(M_SPARC), "SPARC");
        assert_eq!(machine_type_name(M_ARM), "ARM");
        assert_eq!(machine_type_name(M_AARCH64), "AARCH64");
        assert_eq!(machine_type_name(M_UNKNOWN), "UNKNOWN");
        assert_eq!(machine_type_name(0xFE), "UNKNOWN"); // unrecognized
    }

    #[test]
    fn test_language_spec_known_types() {
        let spec = language_spec_for(M_386, true);
        assert!(spec.is_some());
        let (lang, compiler) = spec.unwrap();
        assert!(lang.contains("x86"));
        assert!(lang.contains("LE"));
        assert_eq!(compiler, "gcc");
    }

    #[test]
    fn test_language_spec_sparc() {
        let spec = language_spec_for(M_SPARC, false);
        assert!(spec.is_some());
        let (lang, _) = spec.unwrap();
        assert!(lang.contains("sparc"));
        assert!(lang.contains("BE"));
    }

    #[test]
    fn test_language_spec_unknown_type() {
        let spec = language_spec_for(0xFE, true);
        assert!(spec.is_none());
    }

    #[test]
    fn test_language_spec_arm() {
        let spec = language_spec_for(M_ARM, true);
        assert!(spec.is_some());
        let (lang, _) = spec.unwrap();
        assert!(lang.contains("ARM"));
    }

    #[test]
    fn test_language_spec_riscv() {
        let spec = language_spec_for(M_RISCV, true);
        assert!(spec.is_some());
        let (lang, _) = spec.unwrap();
        assert!(lang.contains("RISCV"));
    }

    #[test]
    fn test_all_netbsd_types_have_specs() {
        let netbsd_types = [
            M_386_NETBSD,
            M_M68K_NETBSD,
            M_SPARC_NETBSD,
            M_PMAX_NETBSD,
            M_VAX_NETBSD,
            M_ALPHA_NETBSD,
            M_ARM6_NETBSD,
            M_POWERPC_NETBSD,
            M_X86_64_NETBSD,
            M_SPARC64_NETBSD,
        ];
        for &t in &netbsd_types {
            assert!(
                language_spec_for(t, true).is_some() || language_spec_for(t, false).is_some(),
                "No language spec for machine type 0x{:02X}",
                t
            );
        }
    }
}
