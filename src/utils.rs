// Copyright 2021 Guanhao Yin <sopium@mysterious.site>

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

use num_traits::{PrimInt, Unsigned};

pub fn bit_len<K>() -> u32 {
    (std::mem::size_of::<K>() * 8) as u32
}

pub fn to_mask<K>(prefix_len: u32) -> K
where
    K: Unsigned + PrimInt,
{
    match prefix_len {
        0 => K::zero(),
        _ => K::max_value().unsigned_shl(bit_len::<K>() - prefix_len),
    }
}

pub fn next_bit_mask1<K>(len: u32) -> K
where
    K: Unsigned + PrimInt,
{
    (K::one().rotate_right(1)).unsigned_shr(len)
}

pub fn common_prefix_len<K>(k1: K, len1: u32, k2: K, len2: u32) -> u32
where
    K: Unsigned + PrimInt,
{
    let smaller_len = std::cmp::min(len1, len2);
    std::cmp::min(smaller_len, (k1 ^ k2).leading_zeros())
}
