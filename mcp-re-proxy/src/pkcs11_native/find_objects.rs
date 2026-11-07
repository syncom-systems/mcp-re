//! `C_FindObjects` over a session view: the paged walk and its handle bound.

use cryptoki_sys::CK_ATTRIBUTE;
use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_ULONG;

use super::check;
use super::AttributeTemplate;
use super::Pkcs11Error;
use super::SessionRef;

/// Upper bound on the handles one `C_FindObjects` walk may accumulate: a module whose
/// find cursor never advances returns full pages forever, growing the vector without
/// limit and never leaving the loop. A key lookup here expects exactly ONE object.
const MAX_OBJECT_HANDLES: usize = 1024;

/// Handles requested per `C_FindObjects` call.
const PAGE: usize = 16;

impl SessionRef<'_> {
    /// Find all object handles matching `template` (init / iterate / final). Drives the
    /// standard `C_FindObjectsInit` → `C_FindObjects` (paged) → `C_FindObjectsFinal`
    /// sequence and always finalizes, even on an iterate error.
    pub fn find_objects(
        &self,
        template: &AttributeTemplate,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, Pkcs11Error> {
        let attrs = template.as_ck_attributes();
        // Resolve the terminator BEFORE the find is initiated. Discovering a missing
        // `C_FindObjectsFinal` afterwards would leave the operation active on this
        // session, and every later `C_FindObjectsInit` on it returns CKR_OPERATION_ACTIVE.
        // SAFETY: function-list non-null; this reads one `Option` field out of it.
        let finalize = unsafe { func!(self.function_list, C_FindObjectsFinal) };
        // SAFETY: function-list non-null; `C_FindObjectsInit` checked non-null by
        // `func!`. `attrs` is a live slice of CK_ATTRIBUTE for the duration of the
        // call; we pass its base pointer and exact length.
        unsafe {
            let init = func!(self.function_list, C_FindObjectsInit);
            let rv = init(
                self.handle,
                attrs.as_ptr() as *mut CK_ATTRIBUTE,
                attrs.len() as CK_ULONG,
            );
            check(rv, "C_FindObjectsInit")?;
        }

        let result = self.find_objects_collect();

        // Always finalize the find operation, regardless of the iterate result.
        // SAFETY: `finalize` was pulled non-null from the function list before the find
        // began; it takes only the session handle.
        let final_rv = unsafe { finalize(self.handle) };
        let handles = result?;
        check(final_rv, "C_FindObjectsFinal")?;
        Ok(handles)
    }

    /// Iterate `C_FindObjects` in pages until it reports zero new handles.
    /// (Helper for [`Self::find_objects`]; the caller finalizes.)
    fn find_objects_collect(&self) -> Result<Vec<CK_OBJECT_HANDLE>, Pkcs11Error> {
        let mut handles: Vec<CK_OBJECT_HANDLE> = Vec::new();
        while self.collect_page(&mut handles)? {}
        Ok(handles)
    }

    /// Fetch one page and append it; whether another page may follow, which it can only
    /// when this one came back full.
    fn collect_page(&self, handles: &mut Vec<CK_OBJECT_HANDLE>) -> Result<bool, Pkcs11Error> {
        let mut page: [CK_OBJECT_HANDLE; PAGE] = [0; PAGE];
        let found = self.find_page(&mut page)?;
        if found == 0 {
            return Ok(false);
        }
        accumulate(handles, &page[..found])?;
        Ok(found == PAGE)
    }

    /// One `C_FindObjects` call into `page`: the count the module reports it wrote,
    /// refused when it exceeds the page.
    fn find_page(&self, page: &mut [CK_OBJECT_HANDLE; PAGE]) -> Result<usize, Pkcs11Error> {
        let mut found: CK_ULONG = 0;
        // SAFETY: function-list non-null; `C_FindObjects` checked non-null by
        // `func!`. `page` is a fixed PAGE-element buffer; we pass its pointer,
        // PAGE as the max, and `&mut found` for the count actually written.
        unsafe {
            let find = func!(self.function_list, C_FindObjects);
            let rv = find(self.handle, page.as_mut_ptr(), PAGE as CK_ULONG, &mut found);
            check(rv, "C_FindObjects")?;
        }
        let found = found as usize;
        if found > PAGE {
            return Err(Pkcs11Error::Protocol(format!(
                "C_FindObjects reported {found} handles into a {PAGE}-slot page"
            )));
        }
        Ok(found)
    }
}

/// Append one page, refusing a walk that has accumulated past [`MAX_OBJECT_HANDLES`].
fn accumulate(
    handles: &mut Vec<CK_OBJECT_HANDLE>,
    page: &[CK_OBJECT_HANDLE],
) -> Result<(), Pkcs11Error> {
    handles.extend_from_slice(page);
    if handles.len() > MAX_OBJECT_HANDLES {
        return Err(Pkcs11Error::Protocol(format!(
            "C_FindObjects returned more than {MAX_OBJECT_HANDLES} handles; refusing to \
             accumulate further"
        )));
    }
    Ok(())
}
