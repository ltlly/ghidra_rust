//! SOM sys_clock structure ported from Ghidra's `SomSysClock.java`.
//!
//! Represents a SOM `sys_clock` structure -- a timestamp with seconds and
//! nanoseconds since the Unix epoch.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomSysClock`.
pub const SOM_SYS_CLOCK_SIZE: usize = 0x08;

/// Represents a SOM `sys_clock` structure.
///
/// Contains a timestamp with seconds since January 1, 1970 (at 0:00 GMT)
/// and nanoseconds within that second (requires 30 bits to represent).
///
/// Ported from `ghidra.app.util.bin.format.som.SomSysClock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SomSysClock {
    /// Number of seconds that have elapsed since January 1, 1970 (at 0:00 GMT).
    pub seconds: u32,
    /// Nano second of the second (which requires 30 bits to represent).
    pub nano: u32,
}

impl SomSysClock {
    /// Parse a `SomSysClock` from a binary reader at the current position.
    ///
    /// # Errors
    ///
    /// Returns `SomException` if an I/O error occurs.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let seconds = reader.read_next_u32().map_err(SomException::from)?;
        let nano = reader.read_next_u32().map_err(SomException::from)?;
        Ok(Self { seconds, nano })
    }

    /// Returns the number of seconds since the Unix epoch.
    pub fn seconds(&self) -> u32 {
        self.seconds
    }

    /// Returns the nanosecond component.
    pub fn nano_seconds(&self) -> u32 {
        self.nano
    }
}

impl StructConverter for SomSysClock {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "sys_clock".to_string(),
            size: SOM_SYS_CLOCK_SIZE as u32,
            fields: vec![
                ("seconds".into(), DataTypeDescription::DWord),
                ("nano".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomSysClock {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_u32(self.seconds);
        writer.write_u32(self.nano);
        Ok(())
    }
}

impl fmt::Display for SomSysClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomSysClock {{ seconds={}, nano={} }}",
            self.seconds, self.nano
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sys_clock_bytes(seconds: u32, nano: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&seconds.to_le_bytes());
        data.extend_from_slice(&nano.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_sys_clock() {
        let data = make_sys_clock_bytes(1234567890, 999999999);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let clock = SomSysClock::parse(&mut reader).unwrap();

        assert_eq!(clock.seconds(), 1234567890);
        assert_eq!(clock.nano_seconds(), 999999999);
    }

    #[test]
    fn test_parse_sys_clock_zero() {
        let data = make_sys_clock_bytes(0, 0);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let clock = SomSysClock::parse(&mut reader).unwrap();

        assert_eq!(clock.seconds(), 0);
        assert_eq!(clock.nano_seconds(), 0);
    }

    #[test]
    fn test_parse_sys_clock_truncated() {
        let data = vec![0x01, 0x02, 0x03]; // too short
        let mut reader = BinaryReader::from_bytes(&data, true);
        let result = SomSysClock::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_sys_clock_struct_converter() {
        let clock = SomSysClock {
            seconds: 100,
            nano: 200,
        };
        let dt = clock.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "sys_clock");
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].0, "seconds");
                assert_eq!(fields[1].0, "nano");
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_sys_clock_write_roundtrip() {
        let data = make_sys_clock_bytes(0xDEADBEEF, 0xCAFEBABE);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let clock = SomSysClock::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        clock.write_to(&mut writer).unwrap();
        let written = writer.into_vec();
        assert_eq!(written, data);
    }

    #[test]
    fn test_sys_clock_display() {
        let clock = SomSysClock {
            seconds: 1234567890,
            nano: 999999999,
        };
        let s = format!("{}", clock);
        assert!(s.contains("1234567890"));
        assert!(s.contains("999999999"));
    }

    #[test]
    fn test_sys_clock_size() {
        assert_eq!(SOM_SYS_CLOCK_SIZE, 8);
    }

    #[test]
    fn test_sys_clock_equality() {
        let a = SomSysClock {
            seconds: 1,
            nano: 2,
        };
        let b = SomSysClock {
            seconds: 1,
            nano: 2,
        };
        let c = SomSysClock {
            seconds: 1,
            nano: 3,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
