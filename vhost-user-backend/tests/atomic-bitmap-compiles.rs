//! Check that [`AtomicBitmap`] implements [`BitmapReplace`]
//! and [`MemRegionBitmap`] so one can use it for vhost-user
//! backends that do not support migration.

use vhost_user_backend::bitmap::{BitmapReplace, MemRegionBitmap};
use vm_memory::bitmap::AtomicBitmap;

fn check1<T: MemRegionBitmap>() {}

fn check2<T: BitmapReplace>() {}

fn main() {
    check1::<AtomicBitmap>();
    check2::<AtomicBitmap>();
}
