// Copyright 2019 Yin Guanhao <sopium@mysterious.site>

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

use super::{Config, PeerConfig};
use crate::wireguard::{SetPeerCommand, WgState};
use anyhow::Error;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

/// Reload the TiTun device, applying configuration changes.
///
/// Most errors are handled. Shouldn't really return `Err`.
pub async fn reload(wg: &Arc<WgState>, new_config: Config<SocketAddr>) -> Result<(), Error> {
    let _state_change = wg.state_change_advisory.lock().await;

    let current_state = wg.get_state();

    if new_config.interface.private_key != current_state.private_key {
        info!("setting private key");
        wg.set_key(new_config.interface.private_key);
    }

    let new_fwmark = new_config.interface.fwmark.unwrap_or(0);

    if new_fwmark != current_state.fwmark {
        info!("setting fwmark");
        if let Err(e) = wg.set_fwmark(new_fwmark) {
            warn!("failed to set fwmark to {}: {}", new_fwmark, e);
        }
    }

    let new_port = new_config.interface.listen_port.unwrap_or(0);
    if current_state.listen_port != new_port {
        info!("setting listen port");
        if let Err(e) = wg.set_port(new_port).await {
            warn!("failed to set port to {}: {}", new_port, e);
        }
    }

    // I wish BTreeMap has difference and intersection.
    let existing: BTreeSet<_> = current_state.peers.iter().map(|p| p.public_key).collect();
    let new: BTreeSet<_> = new_config.peers.iter().map(|p| p.public_key).collect();

    let mut existing_map: BTreeMap<_, _> = current_state
        .peers
        .into_iter()
        .map(|p| (p.public_key, p))
        .collect();
    let mut new_map: BTreeMap<_, _> = new_config
        .peers
        .into_iter()
        .map(|p| (p.public_key, p))
        .collect();

    // First remove, then modify, then add, to avoid any route conflicts.

    for p in existing.difference(&new) {
        info!("removing peer {}", base64::encode(p));
        wg.remove_peer(p);
    }

    for pk in existing.intersection(&new) {
        let existing = existing_map.remove(pk).unwrap();
        let existing = PeerConfig {
            public_key: existing.public_key,
            preshared_key: existing.preshared_key,
            endpoint: existing.endpoint,
            allowed_ips: existing.allowed_ips,
            keepalive: NonZeroU16::new(existing.persistent_keepalive_interval),
        };
        let new = new_map.remove(pk).unwrap();

        // Don't even call `set_peer` if nothing changes.
        if new != existing {
            info!("setting peer {}", base64::encode(&existing.public_key));

            let command = SetPeerCommand {
                public_key: existing.public_key,
                preshared_key: new.preshared_key,
                endpoint: new.endpoint,
                replace_allowed_ips: true,
                allowed_ips: new.allowed_ips,
                // If new.keepalive is `None`, use `Some(0)` to clear it.
                keepalive: new.keepalive.map(|k| Some(k.get())).unwrap_or(Some(0)),
            };

            wg.set_peer(command)?;
        }
    }

    for (_, new_peer) in new_map {
        info!("adding peer {}", base64::encode(&new_peer.public_key));

        wg.clone().add_peer(&new_peer.public_key)?;

        wg.set_peer(SetPeerCommand {
            public_key: new_peer.public_key,
            endpoint: new_peer.endpoint,
            preshared_key: new_peer.preshared_key,
            allowed_ips: new_peer.allowed_ips,
            replace_allowed_ips: false,
            keepalive: new_peer.keepalive.map(|k| k.get()),
        })?;
    }

    Ok(())
}
