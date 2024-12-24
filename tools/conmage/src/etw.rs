use core::slice;
use std::{collections::{HashMap, HashSet}, ffi::{c_void, OsString}, os::windows::ffi::OsStringExt, sync::{Arc, LazyLock, Mutex}};
use windows::{core::{GUID, PWSTR}, Win32::{Foundation::{CloseHandle, GetLastError}, System::{Diagnostics::Etw::{TdhGetEventInformation, EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_STRING_ONLY, EVENT_PROPERTY_INFO, EVENT_RECORD, TRACE_EVENT_INFO}, Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ}}}};
use crate::datatype::{read_data, DataType};

pub const KERNEL_FILE_GUID: GUID = GUID::from_values(
    0xEDD08927,
    0x9CC4,
    0x4E65,
    [0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89],
);

pub const KERNEL_PROCESS_GUID: GUID = GUID::from_values(
    0x22FB2CD6,
    0x0E7B,
    0x422B,
    [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
);

pub static PROCESS_LIST: LazyLock<Arc<Mutex<HashSet<u32>>>> = LazyLock::new(|| {
    Arc::new(Mutex::new(HashSet::new()))
});

pub static INTYPE_MAP: LazyLock<HashMap<u16, DataType>> = LazyLock::new(|| {
    let mut intype_map: HashMap<u16, DataType> = HashMap::new();
    intype_map.insert(1, DataType::STRING);
    intype_map.insert(2, DataType::STRING);
    intype_map.insert(3, DataType::INT8);
    intype_map.insert(4, DataType::UINT8);
    intype_map.insert(5, DataType::INT16);
    intype_map.insert(6, DataType::UINT16);
    intype_map.insert(7, DataType::INT32);
    intype_map.insert(8, DataType::UINT32);
    intype_map.insert(9, DataType::INT64);
    intype_map.insert(10, DataType::UINT64);
    intype_map.insert(16, DataType::POINTER);
    intype_map
});

pub unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    let fileter_id = {
        if (*event_record).EventHeader.ProviderId == KERNEL_FILE_GUID {
            12
        } else {
            1
        }
    };
    if (*event_record).EventHeader.EventDescriptor.Id == fileter_id { // 10 Create
        let flag = (*event_record).EventHeader.Flags as u32;
        if flag & EVENT_HEADER_FLAG_STRING_ONLY != 0 { 
            println!("true");
        }
        let _pointer_size = {
            if flag & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
                4
            } else {
                8
            }
        };
        if fileter_id == 12{
            let proccess_id = (*event_record).EventHeader.ProcessId;
            let set = PROCESS_LIST.lock().unwrap();
            if !set.contains(&proccess_id) {
                return;
            }
            println!("[file create event]");
            println!("process_id: {}", proccess_id);
            let file_name_offset = 32;
            let file_name_ptr = (*event_record).UserData as *const u8;
            let file_name = tei_string(slice::from_raw_parts(file_name_ptr, (*event_record).UserDataLength as usize), file_name_offset);
            println!("file_name: {}", file_name);
            print_common_info(event_record);
        } else {
            println!("[process start event]");
            let parent_proc_id = (*event_record).EventHeader.ProcessId;
            let proc_ptr = (*event_record).UserData as *const u32;
            let proc_id = *proc_ptr;
            let mut set = PROCESS_LIST.lock().unwrap();
            if !set.contains(&proc_id) {
                set.insert(proc_id);
            }
            let proc_seq_ptr = (*event_record).UserData.add(24) as *const u64;
            let proc_seq = *proc_seq_ptr;
            println!("parent_process_id: {}", parent_proc_id);
            println!("real_proc_id: {}", proc_id);
            println!("proc_seq: {}", proc_seq);
            let proc_path = get_process_path(proc_id);
            println!("proc_path: {}", proc_path);
            print_common_info(event_record);
        }
    }
}

pub unsafe fn print_common_info(event_record: *mut EVENT_RECORD) {
    let user_data_size = (*event_record).UserDataLength;
    let user_data = (*event_record).UserData;
    print_hex(user_data, user_data_size as usize);

    let mut buffer_size = 0u32;
    let _status = TdhGetEventInformation(event_record, None, None, &mut buffer_size);
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
    let event_info_ptr = buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO;

    let status = TdhGetEventInformation(event_record, None, Some(event_info_ptr), &mut buffer_size);
    if status != 0 {
        eprintln!("tdhgeteventinformation failed with error: {:?}", status);
        return ;
    }
    // print provider name
    if event_info_ptr.as_ref().unwrap().ProviderNameOffset != 0 {
        let provider_name = tei_string(&buffer, event_info_ptr.as_ref().unwrap().ProviderNameOffset as usize);
        println!("provider_name: {}", provider_name);
    }

    //print task name
    if event_info_ptr.as_ref().unwrap().TaskNameOffset != 0 {
        let task_name = tei_string(&buffer, event_info_ptr.as_ref().unwrap().TaskNameOffset as usize);
        println!("event_name: {}", task_name);
    }

    let top_level_property = event_info_ptr.as_ref().unwrap().TopLevelPropertyCount;
    let event_info = &*event_info_ptr;
    let mut pos = 0;
    for i in 0..top_level_property {
        let event_property_info = &*(&event_info.EventPropertyInfoArray as *const EVENT_PROPERTY_INFO).offset(i as isize);
        print_event_property_info(event_property_info);
        let property_name = tei_string(&buffer, event_property_info.NameOffset as usize);
        println!("pos: {}", pos);
        let property_value = get_property_value(event_property_info, user_data as *const u8, &mut pos);
        println!("property_name: {} , value: {}", property_name, property_value);
        println!();
    }
}

pub unsafe fn print_hex(buffer: *const c_void, size: usize) {
    if buffer.is_null() {
        println!("buffer is null");
        return;
    }

    let byte_slice = slice::from_raw_parts(buffer as *const u8, size);
    for byte in byte_slice {
        print!("{:02X} ", byte);
    }
    println!();
}

pub unsafe fn parse_user_data_info(user_data: *const u8, offset: usize, intype: DataType) -> String {
    match intype {
        DataType::INT8 => {
            let data = read_data::<i8>(user_data, offset);
            format!("{}", data)
        }
        DataType::UINT8 => {
            let data = read_data::<u8>(user_data, offset);
            format!("{}", data)
        }
        DataType::INT16 => {
            let data = read_data::<i16>(user_data, offset);
            format!("{}", data)
        }
        DataType::UINT16 => {
            let data = read_data::<u16>(user_data, offset);
            format!("{}", data)
        }
        DataType::INT32 => {
            let data = read_data::<i32>(user_data, offset);
            format!("{}", data)
        }
        DataType::UINT32 => {
            let data = read_data::<u32>(user_data, offset);
            format!("{}", data)
        }
        DataType::INT64 => {
            let data = read_data::<i64>(user_data, offset);
            format!("{}", data)
        }
        DataType::UINT64 => {
            let data = read_data::<u64>(user_data, offset);
            format!("{}", data)
        }
        DataType::POINTER => {
            let data = read_data::<u64>(user_data, offset);
            format!("{:X}", data)
        }
        DataType::STRING => {
            let wide_ptr = user_data.add(offset) as *const u16;
            let mut length = 0;
            while *wide_ptr.add(length) != 0 {
                length += 1;
            }
            let wide_slice = slice::from_raw_parts(wide_ptr, length);
            OsString::from_wide(wide_slice).to_string_lossy().to_string()
        }
    }
}

pub unsafe fn get_property_value(info: &EVENT_PROPERTY_INFO, user_data: *const u8, pos: &mut usize) -> String {
    let mut ret = String::new();
    if info.Flags.0 & 0x1 != 0 {
        println!("property_StructType");
        ret = String::from("not supported type yet");  
    } else if info.Flags.0 & 0x1 == 0 {
        println!("property_nonStructType");
        let intype = info.Anonymous1.nonStructType.InType;
        println!("intype: {}", intype);
        let data_type = match INTYPE_MAP.get(&intype) {
            Some(data_type) => data_type,
            None => {
                return String::from("not supported type");
            }
        };
        let length = {
            if info.Anonymous3.length == 0 {
                8
            } else {
                info.Anonymous3.length
            }
        };
        let offset = *pos;
        ret = parse_user_data_info(user_data, offset, data_type.clone());
        *pos += length as usize;
    } else if info.Flags.0 & 0x80 !=  0 {
        println!("property_CustomSchema");
        ret = String::from("not supported type yet");  
    }
    ret
}

pub fn print_event_property_info(info: &EVENT_PROPERTY_INFO) {
    println!("property_Flags : {:?}", info.Flags);
    println!("property_NameOffset : {:?}", info.NameOffset);
    if info.Flags.0 & 0x1 != 0 {
        println!("property_StructType");
        unsafe {
            println!("  {:?}", info.Anonymous1.structType);
        }
    } else if info.Flags.0 & 0x1 == 0 {
        println!("property_nonStructType");
        unsafe {
            println!("  {:?}", info.Anonymous1.nonStructType);
        }
    } else if info.Flags.0 & 0x80 !=  0 {
        println!("property_CustomSchema");
        unsafe {
            println!("  {:?}", info.Anonymous1.customSchemaType);
        }
    }
    if info.Flags.0 & 0x4 != 0 {
        unsafe {
            println!("property_countPropertyIndex : {:?}", info.Anonymous2.countPropertyIndex);
        }
    } else {
        unsafe {
            println!("property_count : {:?}", info.Anonymous2.count);
        }
    }
    if info.Flags.0 & 0x2 != 0 {
        unsafe {
            println!("property_lengthPropertyIndex : {:?}", info.Anonymous3.lengthPropertyIndex);
        }
    } else {
        unsafe {
            println!("property_length : {:?}", info.Anonymous3.length);
        }
    }
    unsafe {
        println!("property_reserved : {:?}", info.Anonymous4.Reserved);
    }
    if info.Flags.0 & 0x40 != 0 {
        unsafe {
            println!("property_tags : {:?}", info.Anonymous4.Anonymous._bitfield);
        }
    }
}

pub unsafe fn get_process_path(pid: u32) -> String {
    let process_handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("openprocess failed with error: {:?}",e);
            return String::from("cant not get process handle");
        }
    };
    if process_handle.is_invalid() {
        eprintln!("openprocess failed with error: {:?}", GetLastError());
        return String::from("bad path");
    }
    let mut buffer: Vec<u16> = vec![0; 260];
    let mut size = buffer.len() as u32;

    if QueryFullProcessImageNameW(process_handle, PROCESS_NAME_FORMAT(0), PWSTR(buffer.as_mut_ptr() as *mut u16), &mut size).is_ok() {
        let _ = CloseHandle(process_handle);
        let os_string = OsString::from_wide(&buffer[..size as usize]);
        os_string.to_string_lossy().into_owned()
    } else {
        let _ = CloseHandle(process_handle);
        eprintln!("queryfullprocessimagename failed with error: {:?}", GetLastError());
        String::from("bad path")
    }
}

pub unsafe fn tei_string(tei_buffer: &[u8], offset: usize) -> String {
    let wide_ptr = tei_buffer.as_ptr().add(offset) as *const u16;
    let mut length = 0;

    while *wide_ptr.add(length) != 0 {
        length += 1;
    }
    let wide_slice = slice::from_raw_parts(wide_ptr, length);
    let os_string = OsString::from_wide(wide_slice);

    os_string.to_string_lossy().to_string()
}