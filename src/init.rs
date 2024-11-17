use std::{mem::MaybeUninit, ptr};

pub(crate) struct TagUninit<T> {
    is_init: bool,
    value: MaybeUninit<T>,
}

/// A MaybeUninit wrapper with a tag declaring whether or not it is initialized.
///
/// If it is initialized, values are `drop`ed as usual.
///
/// Ideally this would be an enum but I couldn't figure out how to assume_init with an enum without
/// copying the data.
impl<T> TagUninit<T> {
    pub(crate) const fn new_uninit() -> Self {
        Self {
            is_init: false,
            value: MaybeUninit::uninit(),
        }
    }

    pub(crate) fn get(&self) -> Option<&T> {
        match self.is_init {
            true => {
                // SAFETY: `self.value` is initialized.
                let ptr = unsafe { self.value.assume_init_ref() };
                Some(ptr)
            },
            false => None,
        }
    }

    pub(crate) fn get_mut(&mut self) -> Option<&mut T> {
        match self.is_init {
            true => {
                // SAFETY: `self.value` is initialized.
                let ptr = unsafe { self.value.assume_init_mut() };
                Some(ptr)
            },
            false => None,
        }
    }

    pub(crate) fn get_uninit(&mut self) -> &mut MaybeUninit<T> {
        &mut self.value
    }

    pub(crate) unsafe fn assume_init(&mut self) {
        self.is_init = true;
    }

    pub(crate) fn uninit(&mut self) {
        if self.is_init() {
            // SAFETY: the pointer is valid and we're uninitializing the value.
            unsafe { ptr::drop_in_place((&raw mut self.value) as *mut T) }
        }
        self.is_init = false;
    }

    pub(crate) fn write(&mut self, value: T) -> &mut T {
        self.uninit();
        self.is_init = true;
        self.value.write(value)
    }

    pub(crate) fn is_init(&self) -> bool {
        self.is_init
    }
}

impl<T> Drop for TagUninit<T> {
    fn drop(&mut self) {
        if self.is_init() {
            // SAFETY: the pointer is valid and we can't read the value again.
            unsafe { ptr::drop_in_place((&raw mut self.value) as *mut T) }
        }
    }
}
