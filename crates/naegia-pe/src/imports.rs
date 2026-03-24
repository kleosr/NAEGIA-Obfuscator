use goblin::pe::PE;

/// Sorted unique DLL names imported by the image (direct static imports only).
pub fn import_dll_names(pe: &PE<'_>) -> Vec<String> {
    let mut names: Vec<String> = pe.libraries.iter().map(|s| (*s).to_string()).collect();
    names.sort();
    names.dedup();
    names
}
