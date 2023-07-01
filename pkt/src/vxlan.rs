use super::Serialize;

pub mod flags {
    pub const I: u8 = 8;
}

pub const DEFAULT_PORT: u16 = 4789;

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone, Default)]
pub struct vxlan_hdr {
    pub flags: u8,
    pub reserved: [u8; 3],
    pub vni: u32,
}

impl Serialize for vxlan_hdr {}

impl vxlan_hdr {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            flags: 0,
            reserved: [0; 3],
            vni: 0,
        }
    }

    #[must_use]
    pub const fn with_vni(vni: u32) -> Self {
        Self::new().vni(vni)
    }

    #[must_use]
    pub const fn i(mut self, flag: bool) -> Self {
        if flag {
            self.flags |= flags::I;
        } else {
            self.flags &= !flags::I;
        }
        self
    }

    /// Use x.vni(123).i(false) to get a VNI without setting I flag
    #[must_use]
    pub const fn vni(mut self, vni: u32) -> Self {
        self.vni = (vni << 8).to_be();
        self.i(true)
    }
}
