//! Helper functions for extracting data from programs.

use std::collections::HashSet;
use ghidra_core::addr::Address;
use ghidra_core::listing::ListingRow;
use ghidra_core::program::Program;
use ghidra_core::symbol::{Symbol, SymbolKind};

pub fn function_symbol_names(prog: &Program) -> Vec<&Symbol> {
    prog.symbol_table.iter().filter(|s| s.kind() == SymbolKind::Function).collect()
}

pub fn function_listing_rows<'a>(prog: &'a Program, entry: Address) -> Vec<&'a ListingRow> {
    let all_func_entries: HashSet<Address> = prog.symbol_table.iter()
        .filter(|s| s.kind() == SymbolKind::Function).map(|s| *s.address()).collect();
    let max_instructions: usize = 1024;
    let mut rows = Vec::new();
    let mut addr = entry;
    while rows.len() < max_instructions {
        if addr != entry && all_func_entries.contains(&addr) { break; }
        if let Some(row) = prog.listing.get(&addr) {
            rows.push(row);
            let m = row.mnemonic.text.to_lowercase();
            if m == "ret" || m == "retn" || m == "iret" || m == "sysret" { break; }
            addr = addr.next();
        } else { break; }
    }
    rows
}

pub fn listing_bytes(rows: &[&ListingRow]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for row in rows { bytes.extend(&row.bytes); }
    bytes
}

pub fn listing_mnemonics(rows: &[&ListingRow]) -> Vec<String> {
    rows.iter().map(|r| r.mnemonic.text.clone()).collect()
}

pub fn extract_callees(rows: &[&ListingRow]) -> Vec<Address> {
    let mut callees = Vec::new();
    for row in rows {
        if row.mnemonic.text.to_lowercase() == "call" {
            if let Ok(addr_val) = parse_hex_operand(&row.operands) {
                callees.push(Address::new(addr_val));
            }
        }
    }
    callees
}

pub fn parse_hex_operand(s: &str) -> Result<u64, ()> {
    let s = s.trim();
    if s.is_empty() { return Err(()); }
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let cleaned: String = stripped.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.is_empty() { return Err(()); }
    u64::from_str_radix(&cleaned, 16).map_err(|_| ())
}

pub fn extract_callers(prog: &Program, addr: Address) -> Vec<Address> {
    prog.xrefs.get(&addr).cloned().unwrap_or_default()
}

pub fn levenshtein_distance(a: &[u8], b: &[u8]) -> usize {
    let n = a.len(); let m = b.len();
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

pub fn jaccard_mnemonic_similarity(src_mnems: &[String], dest_mnems: &[String]) -> f64 {
    if src_mnems.is_empty() || dest_mnems.is_empty() { return 0.0; }
    let a_set: HashSet<&str> = src_mnems.iter().map(|s| s.as_str()).collect();
    let b_set: HashSet<&str> = dest_mnems.iter().map(|s| s.as_str()).collect();
    let intersection = a_set.intersection(&b_set).count();
    let union = a_set.union(&b_set).count();
    if union == 0 { 0.0 } else { intersection as f64 / union as f64 }
}

pub fn lcs_length(a: &[String], b: &[String]) -> usize {
    let n = a.len(); let m = b.len();
    if n > 1024 || m > 1024 {
        let b_set: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();
        return a.iter().filter(|x| b_set.contains(x.as_str())).count();
    }
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in 1..=n { for j in 1..=m {
        if a[i - 1] == b[j - 1] { dp[i][j] = dp[i - 1][j - 1] + 1; }
        else { dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]); }
    }}
    dp[n][m]
}
