// SPDX-License-Identifier: MIT

mod gre_common;
pub mod info_gre;
pub mod info_gre6;

pub use self::gre_common::{GreEncapFlags, GreEncapType, GreIOFlags};
pub use self::info_gre::InfoGre;
pub use self::info_gre6::InfoGre6;
