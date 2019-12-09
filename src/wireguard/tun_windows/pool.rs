// Copyright 2019 Guanhao Yin <sopium@mysterious.site>

// This file is part of TiTun.

// TiTun is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// TiTun is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with TiTun.  If not, see <https://www.gnu.org/licenses/>.

use std::thread::sleep;
use std::time::{Duration, Instant};

use super::*;

extern "system" {
    pub fn WintunOpen(name: *const u8, name_len: i32) -> HANDLE;
    pub fn WintunClose(name: *const u8, name_len: i32);
}

pub const HARDWARE_ID: &str = "Wintun";
const HARDWARE_ID_MULTI_SZ: &[u16] = wch!("Wintun\0\0");
const WAIT_REGISTRY_TIMEOUT: Duration = Duration::from_secs(1);

fn wait_for_single_object(obj: HANDLE, timeout: Option<Duration>) -> io::Result<()> {
    let timeout_millis = timeout
        .map(|t| {
            let millis = t.as_millis();
            if millis >= INFINITE.into() {
                panic!("timeout too large")
            }
            millis as u32
        })
        .unwrap_or(INFINITE);
    match unsafe { WaitForSingleObject(obj, timeout_millis) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(()),
        WAIT_TIMEOUT => Err(io::ErrorKind::TimedOut.into()),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => unreachable!(),
    }
}

fn registry_wait_for_value(
    hkey: &winreg::RegKey,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let event = unsafe_h!(CreateEventW(null_mut(), 0, 0, null_mut())).context("CreateEventW")?;
    let deadline = Instant::now() + timeout;
    loop {
        unsafe_l!(RegNotifyChangeKeyValue(
            hkey.raw_handle(),
            0,
            REG_NOTIFY_CHANGE_LAST_SET,
            event.0,
            1,
        ))
        .context("RegNotifyChangeKeyValue")?;
        match hkey.get_raw_value(name) {
            Ok(_) => return Ok(()),
            Err(e) => {
                if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32)
                    || e.raw_os_error() == Some(ERROR_PATH_NOT_FOUND as i32)
                {
                    let timeout = deadline.saturating_duration_since(Instant::now());
                    wait_for_single_object(event.0, Some(timeout))
                        .context("WaitForSingleObject")?;
                } else {
                    return Err(e).context("RegQueryValueExW");
                }
            }
        }
    }
}

fn registry_open_key_wait(
    root: HKEY,
    key: &str,
    access: u32,
    timeout: Duration,
) -> anyhow::Result<winreg::RegKey> {
    let deadline = Instant::now() + timeout;

    let mut k = winreg::RegKey::predef(root as _);

    let mut path_elems = key.split('\\');
    let last = if let Some(last) = path_elems.next_back() {
        last
    } else {
        return Ok(k);
    };

    for p in path_elems {
        let p = WideCString::from_str(p).context("WideCString::from_str")?;

        let event =
            unsafe_h!(CreateEventW(null_mut(), 0, 0, null_mut())).context("CreateEventW")?;

        unsafe_l!(RegNotifyChangeKeyValue(
            k.raw_handle(),
            0,
            REG_NOTIFY_CHANGE_NAME,
            event.0,
            1,
        ))
        .context("RegNotifyChangeKeyValue")?;

        let mut handle_next = null_mut();
        loop {
            match unsafe_l!(RegOpenKeyExW(
                k.raw_handle(),
                p.as_ptr(),
                0,
                KEY_NOTIFY,
                &mut handle_next,
            )) {
                Ok(()) => {
                    k = winreg::RegKey::predef(handle_next);
                    break;
                }
                Err(e) => {
                    if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32)
                        || e.raw_os_error() == Some(ERROR_PATH_NOT_FOUND as i32)
                    {
                        let timeout = deadline.saturating_duration_since(Instant::now());
                        wait_for_single_object(event.0, Some(timeout)).context("wait for event")?;
                    } else {
                        return Err(e).context("RegOpenKeyExW");
                    }
                }
            }
        }
    }

    let last = WideCString::from_str(last).context("WideCString::from_str")?;

    let event = unsafe_h!(CreateEventW(null_mut(), 0, 0, null_mut())).context("CreateEventW")?;

    unsafe_l!(RegNotifyChangeKeyValue(
        k.raw_handle(),
        0,
        REG_NOTIFY_CHANGE_NAME,
        event.0,
        1,
    ))
    .context("RegNotifyChangeKeyValue")?;

    let mut handle_next = null_mut();
    loop {
        match unsafe_l!(RegOpenKeyExW(
            k.raw_handle(),
            last.as_ptr(),
            0,
            access,
            &mut handle_next,
        )) {
            Ok(()) => {
                k = winreg::RegKey::predef(handle_next);
                break;
            }
            Err(e) => {
                if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32)
                    || e.raw_os_error() == Some(ERROR_PATH_NOT_FOUND as i32)
                {
                    let timeout = deadline.saturating_duration_since(Instant::now());
                    wait_for_single_object(event.0, Some(timeout)).context("wait for event")?;
                } else {
                    return Err(e).context("RegOpenKeyExW");
                }
            }
        }
    }

    Ok(k)
}

#[derive(Debug, PartialEq, Eq)]
pub enum MyRegistryValue {
    MultiSz(Vec<String>),
    Sz(String),
}

pub fn get_device_registry_property(
    dev_info: HDEVINFO,
    device_info_data: &mut SP_DEVINFO_DATA,
    property: u32,
) -> anyhow::Result<MyRegistryValue> {
    let mut data_type = 0u32;

    let mut req_size: u32 = 256;
    let buffer = loop {
        let mut buffer = Buffer::new(req_size as usize);
        match unsafe_b!(SetupDiGetDeviceRegistryPropertyW(
            dev_info,
            device_info_data,
            property,
            &mut data_type,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut req_size
        )) {
            Ok(()) => {
                break buffer;
            }
            Err(e) => {
                if e.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                    continue;
                }
                return Err(e).context("SetupDiGetDeviceRegistryPropertyW")?;
            }
        }
    };

    match data_type {
        REG_MULTI_SZ => {
            let strings = WideStr::from_slice(&buffer.as_slice_u16()[..req_size as usize / 2])
                .to_string_lossy();
            let strings = if strings.ends_with("\0\0") {
                &strings[..strings.len() - 2]
            } else {
                &strings[..]
            };
            Ok(MyRegistryValue::MultiSz(
                strings.split('\0').map(|s| s.into()).collect(),
            ))
        }
        REG_SZ => {
            let s = WideCStr::from_slice_with_nul(buffer.as_slice_u16())
                .context("WideCStr::from_slice_with_nul")?
                .to_string_lossy();
            Ok(MyRegistryValue::Sz(s))
        }
        _ => Err(anyhow::anyhow!("unknown data type {}", data_type)),
    }
}

struct DriverInfoDetail {
    data: Buffer,
}

impl DriverInfoDetail {
    fn hardware_id(&self) -> String {
        if self.as_ref().CompatIDsOffset > 1 {
            unsafe { WideCStr::from_ptr_str(self.as_ref().HardwareID.as_ptr()) }.to_string_lossy()
        } else {
            "".into()
        }
    }

    fn compat_ids(&self) -> Vec<String> {
        let d = self.as_ref();
        unsafe {
            WideStr::from_ptr(
                d.HardwareID.as_ptr().add(d.CompatIDsOffset as usize),
                d.CompatIDsLength as usize,
            )
        }
        .to_string_lossy()
        .split('\0')
        .map(|x| x.into())
        .collect()
    }

    fn is_compatible(&self, hardware_id: &str) -> bool {
        let hardware_id = hardware_id.to_lowercase();
        if self.hardware_id().to_lowercase() == hardware_id {
            return true;
        }
        if self
            .compat_ids()
            .into_iter()
            .any(|c| c.to_lowercase() == hardware_id)
        {
            return true;
        }
        false
    }
}

impl AsMut<SP_DRVINFO_DETAIL_DATA_W> for DriverInfoDetail {
    fn as_mut(&mut self) -> &mut SP_DRVINFO_DETAIL_DATA_W {
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            (self.data.as_mut_ptr() as *mut SP_DRVINFO_DETAIL_DATA_W)
                .as_mut()
                .unwrap()
        }
    }
}

impl AsRef<SP_DRVINFO_DETAIL_DATA_W> for DriverInfoDetail {
    fn as_ref(&self) -> &SP_DRVINFO_DETAIL_DATA_W {
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            (self.data.as_ptr() as *const SP_DRVINFO_DETAIL_DATA_W)
                .as_ref()
                .unwrap()
        }
    }
}

fn get_driver_info_detail(
    dev_info: HDEVINFO,
    device_info_data: &mut SP_DEVINFO_DATA,
    drvinfo_data: &mut SP_DRVINFO_DATA_W,
) -> anyhow::Result<DriverInfoDetail> {
    let mut req_size = (mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>() + 127) as u32;
    loop {
        let mut detail = DriverInfoDetail {
            data: Buffer::new(req_size as usize),
        };
        detail.as_mut().cbSize = mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32;
        match unsafe_b!(SetupDiGetDriverInfoDetailW(
            dev_info,
            device_info_data,
            drvinfo_data,
            detail.as_mut(),
            req_size,
            &mut req_size,
        )) {
            Err(e) => {
                if e.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                    continue;
                }
                return Err(e).context("SetupDiGetDriverInfoDetailW");
            }
            Ok(()) => return Ok(detail),
        }
    }
}

fn remove_numbered_suffix(x: &str) -> &str {
    let removed = x.trim_end_matches(|c: char| c.is_digit(10));
    if removed != x && !removed.is_empty() && removed.ends_with(' ') {
        &removed[..removed.len() - 1]
    } else {
        x
    }
}

#[derive(Debug)]
struct NamedMutexGuard {
    mutex: HandleWrapper,
}

impl Drop for NamedMutexGuard {
    fn drop(&mut self) {
        unsafe_b!(ReleaseMutex(self.mutex.0)).unwrap();
    }
}

pub fn remove_device(
    dev_info: HANDLE,
    device_info_data: &mut SP_DEVINFO_DATA,
) -> anyhow::Result<()> {
    let mut remove_device_params = SP_REMOVEDEVICE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
            InstallFunction: DIF_REMOVE,
        },
        Scope: DI_REMOVEDEVICE_GLOBAL,
        HwProfile: 0,
    };

    unsafe_b!(SetupDiSetClassInstallParamsW(
        dev_info,
        device_info_data,
        &mut remove_device_params.ClassInstallHeader as *mut _,
        mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as u32,
    ))
    .context("SetupDiSetClassInstallParamsW")?;

    unsafe_b!(SetupDiCallClassInstaller(
        DIF_REMOVE,
        dev_info,
        device_info_data,
    ))
    .context("SetupDiCallClassInstaller")
}

#[derive(Debug)]
pub struct Pool {
    name: &'static str,
}

pub const WINTUN_POOL: Pool = Pool { name: "WireGuard" };

pub fn wintun_security_attributes() -> anyhow::Result<SECURITY_ATTRIBUTES> {
    static SD: OnceCell<usize> = OnceCell::new();

    let sd = *SD.get_or_try_init(|| {
        let mut sd = unsafe { mem::zeroed() };
        unsafe_b!(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wch_c!("O:SYD:P(A;;GA;;;SY)").as_ptr(),
            1,
            &mut sd,
            null_mut(),
        ))
        .context("ConvertStringSecurityDescriptorToSecurityDescriptorA")?;
        Ok(sd as usize) as anyhow::Result<_>
    })?;

    Ok(SECURITY_ATTRIBUTES {
        bInheritHandle: 0,
        lpSecurityDescriptor: sd as *mut _,
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
    })
}

impl Pool {
    fn initialize_namespace_inner() -> anyhow::Result<HandleWrapper> {
        let mut security_attributes = wintun_security_attributes()?;

        let mut sid = {
            let mut sid: SID = unsafe { mem::zeroed() };
            let mut len = mem::size_of::<SID>() as u32;
            unsafe_b!(CreateWellKnownSid(
                WinLocalSystemSid,
                null_mut(),
                &mut sid as *mut _ as *mut _,
                &mut len,
            ))
            .context("CreateWellKnownSid")?;
            sid
        };

        let boundry = unsafe_h!(CreateBoundaryDescriptorW(wch_c!("Wintun").as_ptr(), 0))
            .context("CreateBoundryDescriptor")?
            // Boundry descriptors must be deleted with DeleteBoundryDescrptor, not
            // CloseHandle.
            .into_inner();
        let mut boundry = scopeguard::guard(boundry, |boundry| unsafe {
            DeleteBoundaryDescriptor(boundry);
        });

        unsafe_b!(AddSIDToBoundaryDescriptor(
            &mut *boundry,
            &mut sid as *mut _ as *mut _
        ))
        .context("AddSIDToBoundaryDescriptor")?;

        loop {
            match unsafe_h!(CreatePrivateNamespaceW(
                &mut security_attributes,
                *boundry,
                wch_c!("Wintun").as_ptr(),
            )) {
                Ok(h) => return Ok(h),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    match unsafe_h!(OpenPrivateNamespaceW(*boundry, wch_c!("Wintun").as_ptr())) {
                        Ok(h) => return Ok(h),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(e).context("OpenPrivateNamespaceA"),
                    }
                }
                Err(e) => return Err(e).context("CreatePrivateNamespaceA"),
            }
        }
    }

    fn initialize_namespace(&self) -> anyhow::Result<()> {
        static NAMESPACE: OnceCell<HandleWrapper> = OnceCell::new();
        NAMESPACE.get_or_try_init(Pool::initialize_namespace_inner)?;
        Ok(())
    }

    fn mutex_name(&self) -> String {
        const MUTEX_LABEL: &[u8] = b"WireGuard Adapter Name Mutex Stable Suffix v1 jason@zx2c4.com";

        let mut b2 = blake2s_simd::State::new();
        b2.update(MUTEX_LABEL);
        // XXX: normalize pool name (NFC).
        b2.update(self.name.as_bytes());
        format!(
            "Wintun\\Wintun-Name-Mutex-{}",
            hex::encode(b2.finalize().as_bytes())
        )
    }

    fn take_named_mutex(&self) -> anyhow::Result<NamedMutexGuard> {
        self.initialize_namespace()
            .context("initialize namespace")?;

        let mutex_name = WideCString::from_str(&self.mutex_name()).unwrap();
        let mut security_attributes = wintun_security_attributes()?;

        let mutex = unsafe_h!(CreateMutexW(
            &mut security_attributes,
            0,
            mutex_name.as_ptr(),
        ))
        .context("CreateMutexA")?;

        wait_for_single_object(mutex.0, None).context("WaitForSingleObject on the named mutex")?;

        Ok(NamedMutexGuard { mutex })
    }

    pub fn get_interface(&self, ifname: &OsStr) -> anyhow::Result<Option<Interface>> {
        let _mutex_guard = self.take_named_mutex()?;

        let dev_info = unsafe_h!(SetupDiGetClassDevsExW(
            &GUID_DEVCLASS_NET,
            null(),
            null_mut(),
            DIGCF_PRESENT,
            null_mut(),
            null(),
            null_mut(),
        ))
        .context("SetupDiGetClassDevsExA")?
        .into_inner();
        scopeguard::defer! {{
            unsafe_b!(SetupDiDestroyDeviceInfoList(dev_info)).unwrap();
        }};
        let ifname = ifname
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("ifname to_str failed"))?
            .to_lowercase();

        for index in 0.. {
            let mut device_info_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
            device_info_data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
            if unsafe { SetupDiEnumDeviceInfo(dev_info, index, &mut device_info_data) } == 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                    break;
                } else {
                    return Err(e).context("SetupDiEnumDeviceInfo");
                }
            }
            // Check the Hardware ID to make sure it's a real Wintun device
            // first. This avoids doing slow operations on non-Wintun devices.
            match get_device_registry_property(dev_info, &mut device_info_data, SPDRP_HARDWAREID) {
                Ok(MyRegistryValue::MultiSz(hwids))
                    if hwids.iter().any(|hwid| hwid == HARDWARE_ID) => {}
                _ => continue,
            }

            let wintun = match Interface::new(dev_info, &mut device_info_data, self) {
                Err(e) => {
                    warn!("failed Interface::new: {:#}", e);
                    continue;
                }
                Ok(w) => w,
            };
            let ifname2 = wintun.name().context("wintun.name()")?;
            let ifname3 = remove_numbered_suffix(&ifname2);

            if ifname == ifname2 || ifname == ifname3 {
                unsafe_b!(SetupDiBuildDriverInfoList(
                    dev_info,
                    &mut device_info_data,
                    SPDIT_COMPATDRIVER
                ))
                .context("SetupDiBuildDriverInfoList")?;
                let mut device_info_data = scopeguard::guard(device_info_data, |mut d| {
                    unsafe_b!(SetupDiDestroyDriverInfoList(
                        dev_info,
                        &mut d,
                        SPDIT_COMPATDRIVER
                    ))
                    .unwrap();
                });

                for index in 0.. {
                    let mut drvinfo_data: SP_DRVINFO_DATA_W = unsafe { mem::zeroed() };
                    drvinfo_data.cbSize = mem::size_of::<SP_DRVINFO_DATA_W>() as u32;
                    if let Err(e) = unsafe_b!(SetupDiEnumDriverInfoW(
                        dev_info,
                        &mut *device_info_data,
                        SPDIT_COMPATDRIVER,
                        index,
                        &mut drvinfo_data,
                    )) {
                        if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                            break;
                        } else {
                            return Err(e).context("SetupDiEnumDriverInfoW");
                        }
                    }
                    let drvinfo_detail_data = get_driver_info_detail(
                        dev_info,
                        &mut *device_info_data,
                        &mut drvinfo_data,
                    )?;
                    if drvinfo_detail_data.is_compatible(HARDWARE_ID) {
                        if self.is_member(dev_info, &mut device_info_data)? {
                            return Ok(Some(wintun));
                        } else {
                            return Err(io::Error::from(io::ErrorKind::AlreadyExists).into());
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    pub fn create_interface(&self, ifname: &OsStr) -> anyhow::Result<Interface> {
        let _mutex_guard = self.take_named_mutex()?;

        // Create an empty device info set for network adapter device class.
        let dev_info = unsafe_h!(SetupDiCreateDeviceInfoListExW(
            &GUID_DEVCLASS_NET,
            null_mut(),
            wch_c!("").as_ptr(),
            null_mut(),
        ))
        .context("SetupDiCreateDeviceInfoListExW")?
        .into_inner();
        scopeguard::defer! {{
            unsafe_b!(SetupDiDestroyDeviceInfoList(dev_info)).unwrap();
        }};

        // Get the device class name from GUID.
        let class_name = {
            let mut class_name = vec![0u16; MAX_CLASS_NAME_LEN];
            let mut req_size = 0;
            unsafe_b!(SetupDiClassNameFromGuidExW(
                &GUID_DEVCLASS_NET,
                class_name.as_mut_ptr(),
                class_name.len() as u32,
                &mut req_size,
                wch_c!("").as_ptr(),
                null_mut(),
            ))
            .context("SetupDiClassNameFromGuidExW")?;
            WideCString::from_vec_with_nul(class_name).context("SetupDiClassNameFromGuidExW")?
        };

        // Create a new device info element and add it to the device info set.
        let device_type_name = WideCString::from_str(self.device_type_name()).unwrap();
        let mut device_info_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
        device_info_data.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as u32;
        unsafe_b!(SetupDiCreateDeviceInfoW(
            dev_info,
            class_name.as_ptr(),
            &GUID_DEVCLASS_NET,
            device_type_name.as_ptr(),
            null_mut(),
            DICD_GENERATE_ID,
            &mut device_info_data,
        ))
        .context("SetupDiCreateDeviceInfo")?;

        // Set quiet installation.
        let mut params: SP_DEVINSTALL_PARAMS_W = unsafe { mem::zeroed() };
        params.cbSize = mem::size_of::<SP_DEVINSTALL_PARAMS_W>() as u32;
        unsafe_b!(SetupDiGetDeviceInstallParamsW(
            dev_info,
            &mut device_info_data,
            &mut params,
        ))
        .context("SetupDiGetDeviceInstallParams")?;
        params.Flags |= DI_QUIETINSTALL;
        unsafe_b!(SetupDiSetDeviceInstallParamsW(
            dev_info,
            &mut device_info_data,
            &mut params,
        ))
        .context("SetupDiSetDeviceInstallParamsW")?;

        // Set a device information element as the selected member of a device
        // information set.
        unsafe_b!(SetupDiSetSelectedDevice(dev_info, &mut device_info_data,))
            .context("SetupDiSetSelectedDevice")?;

        // Set Plug&Play device hardware ID property.
        unsafe_b!(SetupDiSetDeviceRegistryPropertyW(
            dev_info,
            &mut device_info_data,
            SPDRP_HARDWAREID,
            HARDWARE_ID_MULTI_SZ.as_ptr() as *const u8,
            (HARDWARE_ID_MULTI_SZ.len() * 2) as u32,
        ))
        .context("SetupDiSetDeviceRegistryPropertyW")?;

        // Build driver info list.
        unsafe_b!(SetupDiBuildDriverInfoList(
            dev_info,
            &mut device_info_data,
            SPDIT_COMPATDRIVER
        ))
        .context("SetupDiBuildDriverInfoList")?;
        let mut device_info_data = scopeguard::guard(device_info_data, |mut d| {
            unsafe_b!(SetupDiDestroyDriverInfoList(
                dev_info,
                &mut d,
                SPDIT_COMPATDRIVER
            ))
            .unwrap();
        });

        // Find and select driver.
        let mut best_driver_date: FILETIME = unsafe { mem::zeroed() };
        let mut best_driver_version: u64 = 0;

        for index in 0.. {
            let mut drvinfo_data: SP_DRVINFO_DATA_W = unsafe { mem::zeroed() };
            drvinfo_data.cbSize = mem::size_of::<SP_DRVINFO_DATA_W>() as u32;
            if let Err(e) = unsafe_b!(SetupDiEnumDriverInfoW(
                dev_info,
                &mut *device_info_data,
                SPDIT_COMPATDRIVER,
                index,
                &mut drvinfo_data,
            )) {
                if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                    break;
                } else {
                    return Err(e).context("SetupDiEnumDriverInfoW");
                }
            }

            debug!(
                "found driver with description: {}, version: 0x{:x}",
                WideCStr::from_slice_with_nul(&drvinfo_data.Description[..])
                    .unwrap()
                    .to_string_lossy(),
                drvinfo_data.DriverVersion
            );

            let newer = (
                drvinfo_data.DriverDate.dwHighDateTime,
                drvinfo_data.DriverDate.dwLowDateTime,
                drvinfo_data.DriverVersion,
            ) > (
                best_driver_date.dwHighDateTime,
                best_driver_date.dwLowDateTime,
                best_driver_version,
            );

            // Continue if the driver is newer than the current match.
            if newer {
                let drvinfo_detail_data =
                    get_driver_info_detail(dev_info, &mut *device_info_data, &mut drvinfo_data)?;
                if drvinfo_detail_data.is_compatible(HARDWARE_ID) {
                    debug!("driver selected");
                    unsafe_b!(SetupDiSetSelectedDriverW(
                        dev_info,
                        &mut *device_info_data,
                        &mut drvinfo_data,
                    ))
                    .context("SetupDiSetSelectedDriverW")?;

                    best_driver_date = drvinfo_data.DriverDate;
                    best_driver_version = drvinfo_data.DriverVersion;
                }
            }
        }

        if best_driver_version == 0 {
            bail!("No driver for device {} installed", HARDWARE_ID);
        }

        let mut device_info_data = scopeguard::guard(device_info_data, |mut device_info_data| {
            remove_device(dev_info, &mut *device_info_data).unwrap_or_else(|e| {
                warn!("failed to remove device: {:#}", e);
            });
        });

        // Call appropriate class installer.
        unsafe_b!(SetupDiCallClassInstaller(
            DIF_REGISTERDEVICE,
            dev_info,
            &mut **device_info_data,
        ))
        .context("SetupDiCallClassInstaller DIF_REGISTERDEVICE")?;

        // Register device co-installers if any. (Ignore errors)
        let _ = unsafe_b!(SetupDiCallClassInstaller(
            DIF_REGISTER_COINSTALLERS,
            dev_info,
            &mut **device_info_data,
        ));

        let net_dev_reg_key = {
            let t0 = Instant::now();

            loop {
                match unsafe_h!(SetupDiOpenDevRegKey(
                    dev_info,
                    &mut **device_info_data,
                    DICS_FLAG_GLOBAL,
                    0,
                    DIREG_DRV,
                    KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_NOTIFY,
                ) as HANDLE)
                {
                    Ok(h) => break Ok(RegKey::predef(h.into_inner() as _)),
                    Err(e) => {
                        if t0.elapsed() > WAIT_REGISTRY_TIMEOUT {
                            break Err(e).context("SetupDiOpenDevRegKey");
                        } else {
                            sleep(Duration::from_millis(50));
                            continue;
                        }
                    }
                }
            }
        }?;
        // TODO: implement requested guid.

        // Install interfaces if any. (Ignore errors)
        let _ = unsafe_b!(SetupDiCallClassInstaller(
            DIF_INSTALLINTERFACES,
            dev_info,
            &mut **device_info_data,
        ));

        // Install the device.
        unsafe_b!(SetupDiCallClassInstaller(
            DIF_INSTALLINTERFACES,
            dev_info,
            &mut **device_info_data,
        ))
        .context("SetupDiCallClassInstaller DIF_INSTALLINTERFACES")?;

        // TODO: check reboot required.

        unsafe_b!(SetupDiSetDeviceRegistryPropertyW(
            dev_info,
            &mut **device_info_data,
            SPDRP_DEVICEDESC,
            device_type_name.as_ptr() as *const u8,
            (device_type_name.len() * 2) as u32,
        ))
        .context("SetupDiSetDeviceRegistryPropertyW SPDRP_DEVICEDESC")?;

        registry_wait_for_value(&net_dev_reg_key, "NetCfgInstanceId", WAIT_REGISTRY_TIMEOUT)
            .context("wait for reg value NetCfgInstanceId")?;
        registry_wait_for_value(&net_dev_reg_key, "NetLuidIndex", WAIT_REGISTRY_TIMEOUT)
            .context("wait for reg value NetLuidIndex")?;
        registry_wait_for_value(&net_dev_reg_key, "*IfType", WAIT_REGISTRY_TIMEOUT)
            .context("wait for reg value *ifType")?;

        let wintun =
            Interface::new(dev_info, &mut **device_info_data, self).context("Interface::new")?;

        // Wait for IpConfig.
        let tcp_ip_adapter_reg_key_name = format!(
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\{}",
            wintun.net_cfg_instance_id_str()
        );
        let tcp_ip_adapter_key = registry_open_key_wait(
            HKEY_LOCAL_MACHINE,
            &tcp_ip_adapter_reg_key_name,
            KEY_QUERY_VALUE | KEY_NOTIFY,
            WAIT_REGISTRY_TIMEOUT,
        )
        .context("open tcp/ip adapter key")?;
        registry_wait_for_value(&tcp_ip_adapter_key, "IpConfig", WAIT_REGISTRY_TIMEOUT)
            .context("wait for registry value IpConfig")?;
        let ip_configs: String = tcp_ip_adapter_key
            .get_value("IpConfig")
            .context("get IpConfig")?;
        let ip_config = ip_configs
            .split('\n')
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to get IpConfig, it is empty"))?;
        if ip_config.is_empty() {
            bail!("failed to get IpConfig, it is empty");
        }

        // Set `EnableDeadGWDetect` to disable dead gateway detection on our interface.
        let tcp_ip_interface_reg_key_name =
            format!("SYSTEM\\CurrentControlSet\\Services\\{}", ip_config);
        let tcp_ip_interface_key = registry_open_key_wait(
            HKEY_LOCAL_MACHINE,
            &tcp_ip_interface_reg_key_name,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            WAIT_REGISTRY_TIMEOUT,
        )
        .context("open tcp/ip interface key")?;
        tcp_ip_interface_key
            .set_value("EnableDeadGWDetect", &0u32)
            .context("set EnableDeadGWDetect")?;

        let ifname = ifname
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("ifname is not valid"))?;

        wintun.set_name(ifname).context("set_name")?;

        // Don't run guard fn to delete interface, because the
        // creation succeded.
        scopeguard::ScopeGuard::into_inner(device_info_data);

        Ok(wintun)
    }

    fn device_type_name(&self) -> String {
        format!("{} Tunnel", self.name)
    }

    fn is_member(
        &self,
        dev_info: HDEVINFO,
        dev_info_data: &mut SP_DEVINFO_DATA,
    ) -> anyhow::Result<bool> {
        let device_desc =
            match get_device_registry_property(dev_info, dev_info_data, SPDRP_DEVICEDESC)? {
                MyRegistryValue::Sz(v) => v,
                _ => bail!("Unexpected data type for SPDRP_DEVICEDESC"),
            };
        let friendly_name =
            match get_device_registry_property(dev_info, dev_info_data, SPDRP_FRIENDLYNAME)? {
                MyRegistryValue::Sz(v) => v,
                _ => bail!("unexpected data type for SPDRP_FRIENDLYNAME"),
            };

        let device_type_name = self.device_type_name();

        Ok(device_desc == device_type_name
            || friendly_name == device_type_name
            || remove_numbered_suffix(&device_desc) == device_type_name
            || remove_numbered_suffix(&friendly_name) == device_type_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutex_name() {
        assert_eq!(WINTUN_POOL.mutex_name(), "Wintun\\Wintun-Name-Mutex-4843d7de9cb25125d50ac5cec3866519a1cab845a26e84d5593f8ab8bbc5fb2c");
    }

    // XXX: this test only really works when running as LocalSystem.
    //
    // You can use .e.g. psexec (from pstools) to run this test as LocalSystem.
    #[test]
    fn test_take_named_mutex() {
        println!("take_named_mutex: {:?}", WINTUN_POOL.take_named_mutex());
    }

    // XXX: this test only really works when running as LocalSystem.
    #[test]
    fn test_get_interface() {
        std::env::set_var("RUST_LOG", "warn");
        let _ = env_logger::try_init();
        println!(
            "get_interface: {:?}",
            WINTUN_POOL.get_interface(OsStr::new("tun0"))
        );
    }

    #[test]
    fn test_create_interface() {
        std::env::set_var("RUST_LOG", "debug");
        let _ = env_logger::try_init();
        println!(
            "create_interface: {:?}",
            WINTUN_POOL.create_interface(OsStr::new("tun0")),
        );
    }
}
