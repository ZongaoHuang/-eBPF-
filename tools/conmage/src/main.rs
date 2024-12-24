mod datatype;
mod etw;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID, ControlTraceW, EVENT_TRACE_CONTROL_STOP,
};

use crate::etw::{KERNEL_FILE_GUID, KERNEL_PROCESS_GUID, event_record_callback};

fn main() {

    unsafe {
        let mut session_properties = vec![0; size_of::<EVENT_TRACE_PROPERTIES>() + 2 * 260];
        let session_propoerties_ptr = session_properties.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        (*session_propoerties_ptr).Wnode.BufferSize = session_properties.len() as u32;
        (*session_propoerties_ptr).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*session_propoerties_ptr).Wnode.ClientContext = 1;
        (*session_propoerties_ptr).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*session_propoerties_ptr).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        let mut session_handle: CONTROLTRACE_HANDLE = CONTROLTRACE_HANDLE { Value: 0 };
        let session_name = OsStr::new("filemonitorsession").encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let session_name_pcwstr = PCWSTR(session_name.as_ptr());
        let status = StartTraceW(&mut session_handle, session_name_pcwstr, session_propoerties_ptr);
        if status == WIN32_ERROR(183) { // ERROR_ALREADY_EXISTS
            let old_session_handle = CONTROLTRACE_HANDLE { Value: 0 };
            let stop_status = ControlTraceW(
                old_session_handle,
                session_name_pcwstr,
                session_propoerties_ptr,
                EVENT_TRACE_CONTROL_STOP,
            );
            if stop_status != ERROR_SUCCESS {
                eprintln!("Failed to stop existing session: {:?}", stop_status);
                return;
            }
            
            // 重新尝试启动会话
            let status = StartTraceW(&mut session_handle, session_name_pcwstr, session_propoerties_ptr);
            if status != ERROR_SUCCESS {
                eprintln!("starttrace failed with error: {:?}", status);
                return;
            }
        } else if status != ERROR_SUCCESS {
            eprintln!("starttrace failed with error: {:?}", status);
            return;
        }

        // 22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716

        let status = EnableTraceEx2(
            session_handle,
            &KERNEL_PROCESS_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            0,
            0,
            0,
            Some(ptr::null_mut())
        );

        if status != ERROR_SUCCESS {
            eprintln!("enabletrace failed with error: {:?}", status);
            return ;
        }

        let status = EnableTraceEx2(session_handle,
            &KERNEL_FILE_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                0,
                0,
                0,
                Some(ptr::null_mut())
        );
        if status != ERROR_SUCCESS {
            eprintln!("enabletrace failed with error: {:?}", status);
            return ;
        }

        let mut trace_logfile = EVENT_TRACE_LOGFILEW::default();
        trace_logfile.LoggerName = PWSTR(session_name.as_ptr() as *mut u16);
        trace_logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        trace_logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

        let comsumer_handle = OpenTraceW(&mut trace_logfile);


        let status = ProcessTrace(&[comsumer_handle], Some(ptr::null_mut()), Some(ptr::null_mut()));
        if status != ERROR_SUCCESS {
            eprintln!("processtrace failed with error: {:?}", status);
        } 
    }
}


