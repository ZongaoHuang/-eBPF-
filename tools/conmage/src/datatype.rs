#[derive(Debug, Clone, Copy)]
pub enum DataType {
    INT8,
    UINT8,
    INT16,
    UINT16,
    INT32,
    UINT32,
    INT64,
    UINT64,
    POINTER,
    STRING,
}


pub fn read_data<T>(data: *const u8, offset: usize) -> T {
    unsafe {
        // 确保指针对齐
        let aligned_ptr = data.add(offset);
        let ptr = aligned_ptr as *const T;
        // 检查指针对齐
        if (ptr as usize) % std::mem::align_of::<T>() != 0 {
            // 如果未对齐，创建一个临时缓冲区并复制数据
            let mut temp: T = std::mem::zeroed();
            std::ptr::copy_nonoverlapping(aligned_ptr, &mut temp as *mut T as *mut u8, std::mem::size_of::<T>());
            temp
        } else {
            // 如果已对齐，直接读取
            ptr.read_unaligned()
        }
    }
}