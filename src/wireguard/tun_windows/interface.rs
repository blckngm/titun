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

use super::*;

#[derive(Debug)]
pub struct Interface<'a> {
    net_cfg_instance_id: CLSID,
    #[allow(dead_code)]
    net_luid_index: u32,
    #[allow(dead_code)]
    if_type: u32,
    dev_instance_id: String,
    #[allow(dead_code)]
    pool: &'a Pool,
}

fn clsid_from_string(clsid_str: &str) -> anyhow::Result<CLSID> {
    unsafe {
        let mut result: CLSID = mem::zeroed();
        let clsid_str = WideCString::from_str(clsid_str)?;
        match CLSIDFromString(clsid_str.as_ptr(), &mut result) {
            NOERROR => Ok(result),
            e => Err(anyhow::anyhow!(
                "CLSIDFromString failed with return value {}",
                e
            )),
        }
    }
}

fn clsid_to_string(clsid: &CLSID) -> String {
    let mut result: *mut u16 = null_mut();
    unsafe_l!(StringFromCLSID(clsid, &mut result)).expect("StringFromCLSID");
    scopeguard::defer! {
        unsafe { CoTaskMemFree(result as *mut _); }
    };
    unsafe { WideCStr::from_ptr_str(result) }.to_string_lossy()
}

extern "system" {
    fn NciGetConnectionName(guid: &GUID, name: *mut u8, name_len: u32, out_len: &mut u32) -> u32;
    fn NciSetConnectionName(guid: &GUID, name: *const u16) -> u32;
}

impl<'a> Interface<'a> {
    pub fn new(
        dev_info: HDEVINFO,
        data: &mut SP_DEVINFO_DATA,
        pool: &'a Pool,
    ) -> anyhow::Result<Self> {
        let hkey = unsafe_h!(SetupDiOpenDevRegKey(
            dev_info,
            data,
            DICS_FLAG_GLOBAL,
            0,
            DIREG_DRV,
            KEY_QUERY_VALUE
        ) as HANDLE)
        .context("SetupDiOpenDevRegKey")?
        .into_inner();
        // XXX: it's not pre-defined, but it should work OK.
        let hkey = RegKey::predef(hkey as _);
        let net_cfg_instance_id: String = hkey
            .get_value("NetCfgInstanceId")
            .context("get NetCfgInstanceId")?;
        let net_cfg_instance_id = clsid_from_string(&net_cfg_instance_id)
            .context("clsid_from_string(&net_cfg_instance_id)")?;

        let net_luid_index: u32 = hkey.get_value("NetLuidIndex").context("get NetLuidIndex")?;

        let if_type: u32 = hkey.get_value("*ifType").context("get *ifType")?;

        let dev_instance_id: String = {
            let mut req_size: u32 = 1024;
            let mut buf = vec![0u16; 1024];
            unsafe_b!(SetupDiGetDeviceInstanceIdW(
                dev_info,
                data,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut req_size,
            ))
            .context("SetupDiGetDeviceInstanceIdW")?;
            WideCStr::from_slice_truncate(&buf[..])
                .context("SetupDiGetDeviceInstanceIdW WideCStr::from_slice_truncate")?
                .to_string_lossy()
        };

        Ok(Self {
            net_cfg_instance_id,
            net_luid_index,
            if_type,
            dev_instance_id,
            pool,
        })
    }

    pub fn name(&self) -> anyhow::Result<String> {
        let mut buf = Buffer::new(1024);
        let mut len = buf.len() as u32;
        let r = unsafe {
            NciGetConnectionName(
                &self.net_cfg_instance_id,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut len,
            )
        };
        if r == 0 {
            Ok(WideCStr::from_slice_truncate(buf.as_slice_u16())
                .context("WideCStr::from_slice_truncate")?
                .to_string_lossy())
        } else {
            Err(io::Error::from_raw_os_error(r as i32)).context("NciGetConnectionName")
        }
    }

    pub fn set_name(&self, name: &str) -> anyhow::Result<()> {
        let name = WideCString::from_str(name).context("WideCString::from_str")?;

        match unsafe { NciSetConnectionName(&self.net_cfg_instance_id, name.as_ptr()) } {
            0 => Ok(()),
            err => Err(io::Error::from_raw_os_error(err as i32)).context("NciSetConnectionName"),
        }
    }

    pub fn delete(self) -> anyhow::Result<bool> {
        let dev_info = unsafe_h!(SetupDiGetClassDevsExW(
            &GUID_DEVCLASS_NET,
            null(),
            null_mut(),
            DIGCF_PRESENT,
            null_mut(),
            null(),
            null_mut(),
        ))
        .context("SetupDiGetClassDevsEx")?
        .into_inner();
        scopeguard::defer! {
            unsafe_b!(SetupDiDestroyDeviceInfoList(dev_info)).unwrap();
        };

        let mut dev_info_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
        dev_info_data.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as u32;

        for index in 0.. {
            if unsafe { SetupDiEnumDeviceInfo(dev_info, index, &mut dev_info_data) } == 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                    bail!("failed to find device in device info set");
                } else {
                    return Err(e).context("SetupDiEnumDeviceInfo");
                }
            }
            // Check the Hardware ID to make sure it's a real Wintun device
            // first. This avoids doing slow operations on non-Wintun devices.
            match get_device_registry_property(dev_info, &mut dev_info_data, SPDRP_HARDWAREID) {
                Ok(MyRegistryValue::MultiSz(hwids))
                    if hwids.iter().any(|hwid| hwid == HARDWARE_ID) => {}
                _ => continue,
            }

            match Interface::new(dev_info, &mut dev_info_data, &WINTUN_POOL) {
                Err(e) => {
                    warn!("failed Interface::new: {:#}", e);
                    continue;
                }
                Ok(w) => {
                    fn guid_eq(x: &GUID, y: &GUID) -> bool {
                        (x.Data1, x.Data2, x.Data3, x.Data4) == (y.Data1, y.Data2, y.Data3, y.Data4)
                    }

                    if guid_eq(&w.net_cfg_instance_id, &self.net_cfg_instance_id) {
                        break;
                    }
                }
            }
        }

        remove_device(dev_info, &mut dev_info_data)?;

        // TODO: check reboot required.
        Ok(false)
    }

    #[allow(const_item_mutation)]
    pub fn handle(&self) -> anyhow::Result<HandleWrapper> {
        const GUID_DEVINTERFACE_NET: GUID = GUID {
            Data1: 0xcac8_8484,
            Data2: 0x7515,
            Data3: 0x4c03,
            Data4: [0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61],
        };

        let mut len = 0;
        let instance_id = WideCString::from_str(&self.dev_instance_id).unwrap();
        unsafe_cr!(CM_Get_Device_Interface_List_SizeW(
            &mut len,
            &mut GUID_DEVINTERFACE_NET,
            instance_id.as_ptr() as *mut u16,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
        ))
        .context("CM_Get_Device_Interface_List_SizeW")?;

        let mut interface_list = vec![0u16; len as usize];
        unsafe_cr!(CM_Get_Device_Interface_ListW(
            &mut GUID_DEVINTERFACE_NET,
            instance_id.as_ptr() as *mut u16,
            interface_list.as_mut_ptr(),
            len,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
        ))
        .context("CM_Get_Device_Interface_ListW")?;

        unsafe_h!(CreateFileW(
            interface_list.as_mut_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        ))
        .context("CreateFileW")
    }

    pub fn net_cfg_instance_id_str(&self) -> String {
        clsid_to_string(&self.net_cfg_instance_id)
    }
}
