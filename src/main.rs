use std::ffi::{c_void, CString};

use windows::{
    core::{s, w, PCSTR, PCWSTR, PSTR, PWSTR},
    Win32::{
        Foundation::{HANDLE, PSID},
        Security::{
            AllocateAndInitializeSid, Authorization::ConvertSidToStringSidW, FreeSid,
            Isolation::DeleteAppContainerProfile, SECURITY_APP_PACKAGE_AUTHORITY,
            SID_AND_ATTRIBUTES,
        },
        System::{
            SystemServices::{
                SECURITY_BUILTIN_CAPABILITY_RID_COUNT, SECURITY_CAPABILITY_BASE_RID,
                SECURITY_CAPABILITY_DOCUMENTS_LIBRARY, SECURITY_CAPABILITY_MUSIC_LIBRARY,
                SECURITY_CAPABILITY_PICTURES_LIBRARY, SECURITY_CAPABILITY_VIDEOS_LIBRARY,
                SE_GROUP_ENABLED,
            },
            Threading::{
                CreateProcessAsUserA, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
                WaitForSingleObject, CREATE_NEW_CONSOLE, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
                PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXA,
            },
        },
    },
};

fn run_containerized() {
    let mut capabilities = vec![];
    for capability in [
        SECURITY_CAPABILITY_DOCUMENTS_LIBRARY,
        SECURITY_CAPABILITY_VIDEOS_LIBRARY,
        SECURITY_CAPABILITY_PICTURES_LIBRARY,
        SECURITY_CAPABILITY_MUSIC_LIBRARY,
    ] {
        let mut capability_sid = PSID::default();

        unsafe {
            AllocateAndInitializeSid(
                &SECURITY_APP_PACKAGE_AUTHORITY as *const _,
                TryInto::<u8>::try_into(SECURITY_BUILTIN_CAPABILITY_RID_COUNT).unwrap(),
                SECURITY_CAPABILITY_BASE_RID.try_into().unwrap(),
                capability.try_into().unwrap(),
                0,
                0,
                0,
                0,
                0,
                0,
                &mut capability_sid as *mut _,
            )
            .unwrap();
        }
        let capability_attribute = SID_AND_ATTRIBUTES {
            Sid: capability_sid,
            Attributes: SE_GROUP_ENABLED as _,
        };
        capabilities.push(capability_attribute);
    }
    let result = unsafe {
        windows::Win32::Security::Isolation::CreateAppContainerProfile(
            w!("bax"),
            w!("bax"),
            w!("bax"),
            Some(&capabilities),
        )
    };
    let sid = match result {
        Ok(sid) => sid,
        Err(_) => unsafe {
            println!("deriving instead of creating");
            // for now we just assume it exists already.
            windows::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName(w!(
                "bax"
            ))
            .unwrap()
        },
    };
    let capabilities = windows::Win32::Security::SECURITY_CAPABILITIES {
        AppContainerSid: sid,
        Capabilities: capabilities.as_mut_ptr(),
        CapabilityCount: capabilities.len() as _,
        Reserved: 0,
    };
    let mut thread_attribute_list = unsafe {
        let mut attribute_buff_size = 0;
        let _ = InitializeProcThreadAttributeList(
            windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            1,
            0,
            &mut attribute_buff_size,
        );
        let mut buff = Vec::with_capacity(attribute_buff_size);
        InitializeProcThreadAttributeList(
            windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST(buff.as_mut_ptr()),
            1,
            0,
            &mut attribute_buff_size,
        )
        .unwrap();
        UpdateProcThreadAttribute(
            windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST(buff.as_mut_ptr()),
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(&capabilities as *const _ as *const c_void),
            std::mem::size_of_val(&capabilities),
            None,
            None,
        )
        .unwrap();
        buff.set_len(attribute_buff_size);
        buff
    };

    let mut startup_info = STARTUPINFOEXA {
        StartupInfo: Default::default(),
        lpAttributeList: windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST(
            thread_attribute_list.as_mut_ptr(),
        ),
    };
    startup_info.StartupInfo.cb = std::mem::size_of_val(&startup_info) as _;

    let mut proc: PROCESS_INFORMATION = Default::default();
    let cli =
        CString::new(r#""C:\Program Files\VideoLAN\VLC\vlc.exe" "C:\Users\Awsom\Videos\encoded\goin WILD on bookmaker.mp4""#)
            .unwrap();
    unsafe {
        CreateProcessAsUserA(
            HANDLE(0),
            PCSTR::null(),
            PSTR(cli.into_raw() as _),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
            None,
            None,
            &startup_info as *const STARTUPINFOEXA as *const _,
            &mut proc as *mut _,
        )
        .unwrap();
        WaitForSingleObject(proc.hProcess, INFINITE);
    }
    unsafe { FreeSid(sid) };
    unsafe { DeleteAppContainerProfile(w!("bax")).unwrap() };
}

fn main() {
    run_containerized();
}
