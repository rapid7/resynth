/// Allow conversion of above structs in to byte slices
pub trait AsBytes {
    /* I can't believe this isn't in std somewhere? */
    fn as_bytes(&self) -> &[u8];
}

pub trait Serialize {}

impl<T> AsBytes for T
where
    T: Serialize,
{
    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        let size = std::mem::size_of::<T>();

        unsafe { std::slice::from_raw_parts(&*(self as *const T as *const u8), size) }
    }
}
