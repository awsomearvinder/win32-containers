use std::ffi::{c_void, CString};

use windows::{
    core::{s, w, PCSTR, PCWSTR, PSTR, PWSTR},
    Win32::{
        Foundation::{LocalFree, GENERIC_READ, HANDLE, PSID},
        Security::{
            AllocateAndInitializeSid,
            Authorization::{
                ConvertSidToStringSidW, GetNamedSecurityInfoA, SetEntriesInAclA,
                SetNamedSecurityInfoA, EXPLICIT_ACCESS_A, GRANT_ACCESS, SE_FILE_OBJECT,
                TRUSTEE_IS_OBJECTS_AND_SID, TRUSTEE_IS_SID,
            },
            FreeSid,
            Isolation::DeleteAppContainerProfile,
            DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR,
            SECURITY_APP_PACKAGE_AUTHORITY, SECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES,
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
        let mut old_acls = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoA(
            s!(r#"C:\Users\Awsom\Videos"#),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old_acls),
            None,
            &mut descriptor,
        )
        .unwrap();
        let acl_entries = EXPLICIT_ACCESS_A {
            grfAccessPermissions: GENERIC_READ.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: OBJECT_INHERIT_ACE,
            Trustee: windows::Win32::Security::Authorization::TRUSTEE_A {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation:
                    windows::Win32::Security::Authorization::MULTIPLE_TRUSTEE_OPERATION::default(),
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: windows::Win32::Security::Authorization::TRUSTEE_TYPE::default(),
                ptstrName: PSTR(sid.0 as _),
            },
        };
        let mut new_acls = std::ptr::null_mut();
        SetEntriesInAclA(Some(&[acl_entries]), Some(old_acls), &mut new_acls).unwrap();
        SetNamedSecurityInfoA(
            s!(r#"C:\Users\Awsom\Videos"#),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&*new_acls),
            None,
        )
        .unwrap();
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
        SetNamedSecurityInfoA(
            s!(r#"C:\Users\Awsom\Videos"#),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&*old_acls),
            None,
        )
        .unwrap();
    }
    unsafe { FreeSid(sid) };
    unsafe { DeleteAppContainerProfile(w!("bax")).unwrap() };
}

fn main() {
    run_containerized();
}
