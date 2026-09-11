use crate::cli::{ClassQuery, MemberQuery, Query};
use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use memchr::memmem::Finder;
use std::collections::{BTreeMap, BTreeSet};

/// Class lists at least this large are split across workers during the scan.
const PARALLEL_SCAN_CLASSES: usize = 64;
/// Minimum classes per split; keeps splitting overhead negligible on huge DEXes.
const PARALLEL_SCAN_MIN_CHUNK: usize = 8;

#[derive(Clone, Copy, Debug)]
struct Header {
    strings_size: usize,
    strings_off: usize,
    types_size: usize,
    types_off: usize,
    fields_size: usize,
    fields_off: usize,
    methods_size: usize,
    methods_off: usize,
    classes_size: usize,
    classes_off: usize,
}

#[derive(Clone, Copy, Debug)]
struct MemberId {
    class_idx: u16,
    name_idx: u32,
}

pub fn defines_class(data: &[u8], descriptor: &[u8]) -> Result<bool> {
    let dex = Dex::parse(data)?;
    let Some(type_idx) = dex.find_exact_type(descriptor) else {
        return Ok(false);
    };
    for index in 0..dex.header.classes_size {
        let offset = dex.header.classes_off + index * 32;
        if dex.u32(offset)? == type_idx as u32 {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn class_names(data: &[u8]) -> Result<Vec<String>> {
    let dex = Dex::parse(data)?;
    let mut names = Vec::with_capacity(dex.header.classes_size);
    for index in 0..dex.header.classes_size {
        let class_def = dex.header.classes_off + index * 32;
        names.push(dex.type_name(dex.u32(class_def)? as usize)?);
    }
    Ok(names)
}

pub fn find_references(dex_name: &str, data: &[u8], query: &Query) -> Result<Vec<String>> {
    let dex = Dex::parse(data)?;
    let (kind, targets) = dex.resolve_targets(query)?;
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let targets = Targets::new(targets);
    let hits = dex.scan_all_classes(kind, &targets)?;
    let mut rows = Vec::with_capacity(hits.len());
    for (method_idx, matched) in hits {
        let method = dex.method(method_idx as usize)?;
        let class_name = dex.type_name(method.class_idx as usize)?;
        let method_name = dex.string(method.name_idx as usize)?;
        let mut matched_text = Vec::with_capacity(matched.len());
        for index in matched {
            matched_text.push(dex.target_name(kind, index as usize)?);
        }
        rows.push(format!(
            "{dex_name} | {class_name}->{method_name} | matched=({})",
            matched_text.join("; ")
        ));
    }
    Ok(rows)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefKind {
    String,
    Type,
    Method,
    Field,
}

impl RefKind {
    /// Bit used by the per-opcode kind mask.
    const fn bit(self) -> u8 {
        match self {
            RefKind::String => 1,
            RefKind::Type => 2,
            RefKind::Method => 4,
            RefKind::Field => 8,
        }
    }
}

/// Target indices together with a byte-level pre-filter over them.
///
/// Every reference instruction encodes its index as a little-endian operand at
/// `pc + 2`, so a method whose code does not contain the target's bytes cannot
/// reference it. Decoding a method's instructions costs far more than one
/// `memchr` pass over its code, and most methods reference nothing at all.
struct Targets {
    indices: BTreeSet<u32>,
    /// `None` when the target set is too large for the filter to pay off.
    bytes: Option<TargetBytes>,
}

impl Targets {
    /// Above this many targets the filter scans the code once per target, which
    /// costs more than the instruction decode it would skip.
    const MAX_FILTER_TARGETS: usize = 4;

    fn new(indices: impl IntoIterator<Item = u32>) -> Self {
        let indices: BTreeSet<u32> = indices.into_iter().collect();
        let bytes = (indices.len() <= Self::MAX_FILTER_TARGETS).then(|| TargetBytes::new(&indices));
        Self { indices, bytes }
    }
}

/// Encoded target indices, split by operand width.
struct TargetBytes {
    pairs: Vec<[u8; 2]>,
    quads: Vec<[u8; 4]>,
}

impl TargetBytes {
    fn new(indices: &BTreeSet<u32>) -> Self {
        let mut pairs = Vec::new();
        let mut quads = Vec::new();
        for &index in indices {
            if index <= u32::from(u16::MAX) {
                pairs.push((index as u16).to_le_bytes());
            } else {
                quads.push(index.to_le_bytes());
            }
        }
        Self { pairs, quads }
    }

    /// Whether `code` contains any target index as an operand.
    fn matches(&self, code: &[u8]) -> bool {
        self.pairs.iter().any(|pair| contains_pair(code, *pair))
            || self
                .quads
                .iter()
                .any(|quad| memchr::memmem::find(code, quad).is_some())
    }
}

/// Two-byte search: `memchr` on the first byte, then a check on both sides,
/// because the match may start one byte before the position found.
fn contains_pair(code: &[u8], [first, second]: [u8; 2]) -> bool {
    let mut from = 0;
    while let Some(found) = memchr::memchr(first, &code[from..]) {
        let at = from + found;
        if code.get(at + 1) == Some(&second) || (at > 0 && code[at - 1] == second) {
            return true;
        }
        from = at + 1;
    }
    false
}

struct Dex<'a> {
    data: &'a [u8],
    header: Header,
}

impl<'a> Dex<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x70 || !data.starts_with(b"dex\n") {
            bail!("invalid DEX header");
        }
        let header = Header {
            strings_size: read_u32(data, 0x38)? as usize,
            strings_off: read_u32(data, 0x3c)? as usize,
            types_size: read_u32(data, 0x40)? as usize,
            types_off: read_u32(data, 0x44)? as usize,
            fields_size: read_u32(data, 0x50)? as usize,
            fields_off: read_u32(data, 0x54)? as usize,
            methods_size: read_u32(data, 0x58)? as usize,
            methods_off: read_u32(data, 0x5c)? as usize,
            classes_size: read_u32(data, 0x60)? as usize,
            classes_off: read_u32(data, 0x64)? as usize,
        };
        for (offset, count, width, name) in [
            (header.strings_off, header.strings_size, 4, "string_ids"),
            (header.types_off, header.types_size, 4, "type_ids"),
            (header.fields_off, header.fields_size, 8, "field_ids"),
            (header.methods_off, header.methods_size, 8, "method_ids"),
            (header.classes_off, header.classes_size, 32, "class_defs"),
        ] {
            check_table(data, offset, count, width, name)?;
        }
        Ok(Self { data, header })
    }

    fn u32(&self, offset: usize) -> Result<u32> {
        read_u32(self.data, offset)
    }

    fn string_bytes(&self, index: usize) -> Result<&'a [u8]> {
        if index >= self.header.strings_size {
            bail!("string index out of range");
        }
        let mut offset = self.u32(self.header.strings_off + index * 4)? as usize;
        if offset >= self.data.len() {
            bail!("string_data_off outside DEX");
        }
        read_uleb(self.data, &mut offset)?;
        let tail = self.data.get(offset..).context("bad string data offset")?;
        let end = memchr::memchr(0, tail).context("unterminated DEX string")?;
        Ok(&tail[..end])
    }

    fn string(&self, index: usize) -> Result<String> {
        let bytes = self.string_bytes(index)?;
        Ok(droidsaw_dex::mutf8::decode_mutf8(bytes)
            .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned()))
    }

    fn type_string_idx(&self, index: usize) -> Result<usize> {
        if index >= self.header.types_size {
            bail!("type index out of range");
        }
        Ok(self.u32(self.header.types_off + index * 4)? as usize)
    }

    fn type_name(&self, index: usize) -> Result<String> {
        self.string(self.type_string_idx(index)?)
    }

    fn method(&self, index: usize) -> Result<MemberId> {
        self.member(self.header.methods_off, self.header.methods_size, index)
    }

    fn field(&self, index: usize) -> Result<MemberId> {
        self.member(self.header.fields_off, self.header.fields_size, index)
    }

    fn member(&self, base: usize, size: usize, index: usize) -> Result<MemberId> {
        if index >= size {
            bail!("member index out of range");
        }
        let offset = base + index * 8;
        Ok(MemberId {
            class_idx: read_u16(self.data, offset)?,
            name_idx: self.u32(offset + 4)?,
        })
    }

    fn find_exact_type(&self, descriptor: &[u8]) -> Option<usize> {
        (0..self.header.types_size).find(|&index| {
            self.type_string_idx(index)
                .ok()
                .and_then(|string_idx| self.string_bytes(string_idx).ok())
                == Some(descriptor)
        })
    }

    fn matching_strings(&self, pattern: &str) -> Result<Vec<u32>> {
        if pattern.is_empty() {
            return Ok(Vec::new());
        }
        let needle = encode_mutf8(pattern);
        let finder = Finder::new(&needle);
        let mut out = Vec::new();
        for index in 0..self.header.strings_size {
            if finder.find(self.string_bytes(index)?).is_some() {
                out.push(index as u32);
            }
        }
        Ok(out)
    }

    fn matching_types(&self, pattern: &str) -> Result<Vec<u32>> {
        let strings: BTreeSet<u32> = self.matching_strings(pattern)?.into_iter().collect();
        let mut out = Vec::new();
        for index in 0..self.header.types_size {
            if strings.contains(&(self.type_string_idx(index)? as u32)) {
                out.push(index as u32);
            }
        }
        Ok(out)
    }

    fn resolve_targets(&self, query: &Query) -> Result<(RefKind, Vec<u32>)> {
        match query {
            Query::String(pattern) => Ok((RefKind::String, self.matching_strings(pattern)?)),
            Query::Type(pattern) => Ok((RefKind::Type, self.matching_types(pattern)?)),
            Query::Method(query) => Ok((RefKind::Method, self.matching_members(query, true)?)),
            Query::Field(query) => Ok((RefKind::Field, self.matching_members(query, false)?)),
        }
    }

    fn matching_members(&self, query: &MemberQuery, methods: bool) -> Result<Vec<u32>> {
        let (base, size) = if methods {
            (self.header.methods_off, self.header.methods_size)
        } else {
            (self.header.fields_off, self.header.fields_size)
        };
        let name_finder = query.name.as_deref().map(|pattern| Finder::new(pattern.as_bytes()));
        let class_finder = match &query.class {
            Some(ClassQuery::Fuzzy(pattern)) => Some(Finder::new(pattern.as_bytes())),
            _ => None,
        };
        let mut out = Vec::new();
        for index in 0..size {
            let member = self.member(base, size, index)?;
            let name_matches = match &name_finder {
                Some(finder) => finder.find(self.string_bytes(member.name_idx as usize)?).is_some(),
                None => true,
            };
            if !name_matches {
                continue;
            }
            let class_name_idx = self.type_string_idx(member.class_idx as usize)?;
            let class_bytes = self.string_bytes(class_name_idx)?;
            let class_matches = match &query.class {
                None => true,
                Some(ClassQuery::Exact(name)) => class_bytes == name.as_bytes(),
                Some(ClassQuery::Fuzzy(_)) => class_finder
                    .as_ref()
                    .is_some_and(|finder| finder.find(class_bytes).is_some()),
            };
            if class_matches {
                out.push(index as u32);
            }
        }
        Ok(out)
    }

    fn target_name(&self, kind: RefKind, index: usize) -> Result<String> {
        match kind {
            RefKind::String => self.string(index),
            RefKind::Type => self.type_name(index),
            RefKind::Method | RefKind::Field => {
                let member = if kind == RefKind::Method {
                    self.method(index)?
                } else {
                    self.field(index)?
                };
                Ok(format!(
                    "{}->{}",
                    self.type_name(member.class_idx as usize)?,
                    self.string(member.name_idx as usize)?
                ))
            }
        }
    }

    /// Scans every class definition, optionally splitting the class list across
    /// idle workers.
    ///
    /// A single large DEX otherwise owns one worker for the whole scan while the
    /// rest of the pool waits, which shows up as tail latency once the smaller
    /// entries are done. Hit sets are unioned, so the merged result does not
    /// depend on how the split happened to be stolen.
    fn scan_all_classes(&self, kind: RefKind, targets: &Targets) -> Result<BTreeMap<u32, BTreeSet<u32>>> {
        if self.header.classes_size < PARALLEL_SCAN_CLASSES {
            self.scan_all_classes_sequential(kind, targets)
        } else {
            self.scan_all_classes_parallel(kind, targets)
        }
    }

    fn scan_all_classes_sequential(
        &self,
        kind: RefKind,
        targets: &Targets,
    ) -> Result<BTreeMap<u32, BTreeSet<u32>>> {
        let mut hits = BTreeMap::new();
        for class_index in 0..self.header.classes_size {
            self.scan_class_index(class_index, kind, targets, &mut hits)?;
        }
        Ok(hits)
    }

    fn scan_all_classes_parallel(
        &self,
        kind: RefKind,
        targets: &Targets,
    ) -> Result<BTreeMap<u32, BTreeSet<u32>>> {
        (0..self.header.classes_size)
            .into_par_iter()
            .with_min_len(PARALLEL_SCAN_MIN_CHUNK)
            .try_fold(BTreeMap::new, |mut hits, class_index| {
                self.scan_class_index(class_index, kind, targets, &mut hits)?;
                Ok(hits)
            })
            .try_reduce(BTreeMap::new, |mut left, right| {
                for (method_idx, matched) in right {
                    left.entry(method_idx).or_default().extend(matched);
                }
                Ok(left)
            })
    }

    fn scan_class_index(
        &self,
        class_index: usize,
        kind: RefKind,
        targets: &Targets,
        hits: &mut BTreeMap<u32, BTreeSet<u32>>,
    ) -> Result<()> {
        let class_def = self.header.classes_off + class_index * 32;
        let class_data_off = self.u32(class_def + 24)? as usize;
        if class_data_off != 0 {
            self.scan_class_data(class_data_off, kind, targets, hits)?;
        }
        Ok(())
    }

    fn scan_class_data(
        &self,
        offset: usize,
        kind: RefKind,
        targets: &Targets,
        hits: &mut BTreeMap<u32, BTreeSet<u32>>,
    ) -> Result<()> {
        let mut cursor = offset;
        let static_fields = read_uleb(self.data, &mut cursor)? as usize;
        let instance_fields = read_uleb(self.data, &mut cursor)? as usize;
        let direct_methods = read_uleb(self.data, &mut cursor)? as usize;
        let virtual_methods = read_uleb(self.data, &mut cursor)? as usize;
        for _ in 0..static_fields + instance_fields {
            read_uleb(self.data, &mut cursor)?;
            read_uleb(self.data, &mut cursor)?;
        }
        for count in [direct_methods, virtual_methods] {
            let mut method_idx = 0u32;
            for _ in 0..count {
                method_idx = method_idx
                    .checked_add(read_uleb(self.data, &mut cursor)?)
                    .context("method index overflow")?;
                read_uleb(self.data, &mut cursor)?;
                let code_off = read_uleb(self.data, &mut cursor)? as usize;
                if code_off != 0 {
                    self.scan_code(method_idx, code_off, kind, targets, hits)?;
                }
            }
        }
        Ok(())
    }

    fn scan_code(
        &self,
        method_idx: u32,
        code_off: usize,
        kind: RefKind,
        targets: &Targets,
        hits: &mut BTreeMap<u32, BTreeSet<u32>>,
    ) -> Result<()> {
        let insns_size = self.u32(code_off + 12)? as usize;
        let start = code_off.checked_add(16).context("code offset overflow")?;
        let end = start
            .checked_add(insns_size.checked_mul(2).context("code size overflow")?)
            .context("code range overflow")?;
        let code = self.data.get(start..end).context("code item outside DEX")?;
        if let Some(bytes) = &targets.bytes
            && !bytes.matches(code)
        {
            return Ok(());
        }
        let kind_bit = kind.bit();
        let mut pc = 0usize;
        while pc + 2 <= code.len() {
            let opcode = code[pc];
            let units = OPCODE_UNITS[opcode as usize] as usize;
            let units = if units == 0 {
                instruction_units(code, pc)?
            } else {
                units
            };
            if units == 0 || pc + units * 2 > code.len() {
                bail!("invalid instruction width at code offset {}", start + pc);
            }
            // 0x1b is the only reference instruction with a 32-bit index, and
            // only the string mask can reach it.
            if OPCODE_KINDS[opcode as usize] & kind_bit != 0 {
                let index = if opcode == 0x1b {
                    read_u32(code, pc + 2)?
                } else {
                    read_u16(code, pc + 2)? as u32
                };
                if targets.indices.contains(&index) {
                    hits.entry(method_idx).or_default().insert(index);
                }
            }
            pc += units * 2;
        }
        Ok(())
    }
}

fn encode_mutf8(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for unit in value.encode_utf16() {
        match unit {
            0 => out.extend_from_slice(&[0xc0, 0x80]),
            0x0001..=0x007f => out.push(unit as u8),
            0x0080..=0x07ff => {
                out.push((0xc0 | (unit >> 6)) as u8);
                out.push((0x80 | (unit & 0x3f)) as u8);
            }
            _ => {
                out.push((0xe0 | (unit >> 12)) as u8);
                out.push((0x80 | ((unit >> 6) & 0x3f)) as u8);
                out.push((0x80 | (unit & 0x3f)) as u8);
            }
        }
    }
    out
}

/// Instruction width in code units, or 0 for the opcodes that need the runtime
/// path: `0x00` payloads and unsupported opcodes.
const fn opcode_units(opcode: u8) -> u8 {
    match opcode {
        0x00 => 0,
        0x01
        | 0x04
        | 0x07
        | 0x0a..=0x12
        | 0x1d
        | 0x1e
        | 0x21
        | 0x27
        | 0x28
        | 0x7b..=0x8f
        | 0xb0..=0xcf => 1,
        0x02
        | 0x05
        | 0x08
        | 0x13
        | 0x15
        | 0x16
        | 0x19
        | 0x1a
        | 0x1c
        | 0x1f
        | 0x20
        | 0x22
        | 0x23
        | 0x29
        | 0x2d..=0x3d
        | 0x44..=0x6d
        | 0x90..=0xaf
        | 0xd0..=0xe2
        | 0xfe
        | 0xff => 2,
        0x03
        | 0x06
        | 0x09
        | 0x14
        | 0x17
        | 0x1b
        | 0x24..=0x26
        | 0x2a..=0x2c
        | 0x6e..=0x72
        | 0x74..=0x78
        | 0xfc
        | 0xfd => 3,
        0xfa | 0xfb => 4,
        0x18 => 5,
        _ => 0,
    }
}

/// Bitmask of `RefKind::bit` values whose references this opcode can carry.
const fn opcode_kinds(opcode: u8) -> u8 {
    let mut mask = 0;
    if matches!(opcode, 0x1a | 0x1b) {
        mask |= RefKind::String.bit();
    }
    if matches!(opcode, 0x1c | 0x1f | 0x20 | 0x22..=0x25) {
        mask |= RefKind::Type.bit();
    }
    if matches!(opcode, 0x52..=0x6d) {
        mask |= RefKind::Field.bit();
    }
    if matches!(opcode, 0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb) {
        mask |= RefKind::Method.bit();
    }
    mask
}

/// Width and kind tables, so the instruction loop does two loads instead of two
/// function calls per instruction.
const OPCODE_UNITS: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut opcode = 0;
    while opcode < 256 {
        table[opcode] = opcode_units(opcode as u8);
        opcode += 1;
    }
    table
};

const OPCODE_KINDS: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut opcode = 0;
    while opcode < 256 {
        table[opcode] = opcode_kinds(opcode as u8);
        opcode += 1;
    }
    table
};

fn instruction_units(code: &[u8], pc: usize) -> Result<usize> {
    let opcode = *code.get(pc).context("missing opcode")?;
    if opcode == 0 {
        let ident = read_u16(code, pc)?;
        return match ident {
            0x0100 => Ok(4 + read_u16(code, pc + 2)? as usize * 2),
            0x0200 => Ok(2 + read_u16(code, pc + 2)? as usize * 4),
            0x0300 => {
                let width = read_u16(code, pc + 2)? as usize;
                let size = read_u32(code, pc + 4)? as usize;
                Ok(4 + width
                    .checked_mul(size)
                    .context("array payload overflow")?
                    .div_ceil(2))
            }
            _ => Ok(1),
        };
    }
    match OPCODE_UNITS[opcode as usize] {
        0 => bail!("unsupported opcode 0x{opcode:02x}"),
        units => Ok(units as usize),
    }
}

fn check_table(data: &[u8], offset: usize, count: usize, width: usize, name: &str) -> Result<()> {
    let end = offset
        .checked_add(count.checked_mul(width).context("table size overflow")?)
        .context("table range overflow")?;
    if end > data.len() {
        bail!("bad {name} range");
    }
    Ok(())
}

fn read_uleb(data: &[u8], offset: &mut usize) -> Result<u32> {
    let mut result = 0u32;
    for shift in [0, 7, 14, 21, 28] {
        let byte = *data.get(*offset).context("truncated ULEB128")?;
        *offset += 1;
        result |= u32::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(result);
        }
    }
    bail!("ULEB128 exceeds 5 bytes")
}

pub(crate) fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .context("truncated u16")?
        .try_into()?;
    Ok(u16::from_le_bytes(bytes))
}

pub(crate) fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .context("truncated u32")?
        .try_into()?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn push_uleb(out: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return;
            }
        }
    }

    /// Builds a DEX where every class has one direct method whose body is
    /// `const-string v0, "Authorization"` followed by `return-void`.
    ///
    /// The class count is the knob that selects the sequential or the parallel
    /// scan path, so the same fixture can be used to compare the two directly.
    fn const_string_fixture(class_count: usize) -> Vec<u8> {
        assert!(class_count > 0);
        let mut strings = vec!["Authorization".to_owned()];
        for index in 0..class_count {
            strings.push(format!("LFixture{index};"));
        }
        for index in 0..class_count {
            strings.push(format!("m{index}"));
        }
        let n_strings = strings.len();
        let n_types = class_count + 1;

        let string_ids_off = 0x70;
        let type_ids_off = string_ids_off + n_strings * 4;
        let method_ids_off = type_ids_off + n_types * 4;
        let class_defs_off = method_ids_off + class_count * 8;
        let data_off = class_defs_off + class_count * 32;

        let mut data = Vec::new();
        let mut string_offsets = Vec::with_capacity(n_strings);
        for value in &strings {
            string_offsets.push(data_off + data.len());
            push_uleb(&mut data, value.len() as u32);
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        }

        let mut class_data_offsets = Vec::with_capacity(class_count);
        for index in 0..class_count {
            while !(data_off + data.len()).is_multiple_of(4) {
                data.push(0);
            }
            let code_off = (data_off + data.len()) as u32;
            data.extend_from_slice(&1_u16.to_le_bytes()); // registers_size: v0
            data.extend_from_slice(&0_u16.to_le_bytes()); // ins_size
            data.extend_from_slice(&0_u16.to_le_bytes()); // outs_size
            data.extend_from_slice(&0_u16.to_le_bytes()); // tries_size
            data.extend_from_slice(&0_u32.to_le_bytes()); // debug_info_off
            data.extend_from_slice(&3_u32.to_le_bytes()); // insns_size in code units
            data.extend_from_slice(&0x001a_u16.to_le_bytes()); // const-string v0, #0
            data.extend_from_slice(&0_u16.to_le_bytes());
            data.extend_from_slice(&0x000e_u16.to_le_bytes()); // return-void

            class_data_offsets.push(data_off + data.len());
            data.push(0); // static_fields_size
            data.push(0); // instance_fields_size
            data.push(1); // direct_methods_size
            data.push(0); // virtual_methods_size
            push_uleb(&mut data, index as u32); // method_idx_diff
            push_uleb(&mut data, 0); // access_flags
            push_uleb(&mut data, code_off);
        }

        let total = data_off + data.len();
        let mut out = vec![0_u8; total];
        out[..8].copy_from_slice(b"dex\n039\0");
        write_u32(&mut out, 0x20, total as u32);
        write_u32(&mut out, 0x24, 0x70);
        write_u32(&mut out, 0x28, 0x1234_5678);
        write_u32(&mut out, 0x38, n_strings as u32);
        write_u32(&mut out, 0x3c, string_ids_off as u32);
        write_u32(&mut out, 0x40, n_types as u32);
        write_u32(&mut out, 0x44, type_ids_off as u32);
        write_u32(&mut out, 0x58, class_count as u32);
        write_u32(&mut out, 0x5c, method_ids_off as u32);
        write_u32(&mut out, 0x60, class_count as u32);
        write_u32(&mut out, 0x64, class_defs_off as u32);

        for (index, offset) in string_offsets.iter().enumerate() {
            write_u32(&mut out, string_ids_off + index * 4, *offset as u32);
        }
        write_u32(&mut out, type_ids_off, 0);
        for (index, class_data_off) in class_data_offsets.iter().enumerate() {
            write_u32(&mut out, type_ids_off + (index + 1) * 4, (index + 1) as u32);

            let method = method_ids_off + index * 8;
            write_u16(&mut out, method, (index + 1) as u16);
            write_u16(&mut out, method + 2, 0);
            write_u32(&mut out, method + 4, (1 + class_count + index) as u32);

            let class_def = class_defs_off + index * 32;
            write_u32(&mut out, class_def, (index + 1) as u32);
            write_u32(&mut out, class_def + 8, u32::MAX);
            write_u32(&mut out, class_def + 16, u32::MAX);
            write_u32(&mut out, class_def + 24, *class_data_off as u32);
        }
        out[data_off..].copy_from_slice(&data);
        out
    }

    /// Rows for `find_references` are grouped by ascending method index, which is
    /// the order the hit map iterates in. Cross-DEX ordering/aggregation happens
    /// later in the APK layer.
    fn expected_rows(class_count: usize) -> Vec<String> {
        (0..class_count)
            .map(|index| {
                format!("classes.dex | LFixture{index};->m{index} | matched=(Authorization)")
            })
            .collect()
    }

    #[test]
    fn parallel_and_sequential_scans_produce_identical_hits() {
        let data = const_string_fixture(PARALLEL_SCAN_CLASSES);
        let dex = Dex::parse(&data).unwrap();
        let (kind, targets) = dex
            .resolve_targets(&Query::String("Authorization".to_owned()))
            .unwrap();
        let targets = Targets::new(targets);
        let sequential = dex.scan_all_classes_sequential(kind, &targets).unwrap();
        let parallel = dex.scan_all_classes_parallel(kind, &targets).unwrap();
        assert_eq!(sequential.len(), PARALLEL_SCAN_CLASSES);
        assert_eq!(sequential, parallel);
    }

    #[test]
    fn multi_chunk_parallel_scan_keeps_every_hit() {
        let class_count = PARALLEL_SCAN_CLASSES * 3 + 1;
        let data = const_string_fixture(class_count);
        let rows = find_references(
            "classes.dex",
            &data,
            &Query::String("Authorization".to_owned()),
        )
        .unwrap();
        assert_eq!(rows, expected_rows(class_count));
    }

    fn minimal_class_dex(descriptor: &[u8]) -> Vec<u8> {
        let string_ids_off = 0x70;
        let type_ids_off = 0x74;
        let class_defs_off = 0x78;
        let string_data_off = 0x98;
        let mut data = vec![0; string_data_off + descriptor.len() + 2];
        data[..8].copy_from_slice(b"dex\n039\0");
        data[0x38..0x3c].copy_from_slice(&1_u32.to_le_bytes());
        data[0x3c..0x40].copy_from_slice(&(string_ids_off as u32).to_le_bytes());
        data[0x40..0x44].copy_from_slice(&1_u32.to_le_bytes());
        data[0x44..0x48].copy_from_slice(&(type_ids_off as u32).to_le_bytes());
        data[0x60..0x64].copy_from_slice(&1_u32.to_le_bytes());
        data[0x64..0x68].copy_from_slice(&(class_defs_off as u32).to_le_bytes());
        data[string_ids_off..string_ids_off + 4]
            .copy_from_slice(&(string_data_off as u32).to_le_bytes());
        data[string_data_off] = descriptor.len() as u8;
        data[string_data_off + 1..string_data_off + 1 + descriptor.len()]
            .copy_from_slice(descriptor);
        data
    }

    #[test]
    fn lists_defined_classes_from_class_defs() {
        let data = minimal_class_dex(b"Lcom/example/Main;");
        assert_eq!(class_names(&data).unwrap(), ["Lcom/example/Main;"]);
        assert!(defines_class(&data, b"Lcom/example/Main;").unwrap());
    }

    #[test]
    fn fuzzy_patterns_are_literal_substrings() {
        assert!(Finder::new(b".b[").find(b"a.b[c]").is_some());
        assert!(Finder::new(b"a.c").find(b"abc").is_none());
    }

    #[test]
    fn mutf8_encodes_nul_and_supplementary_characters() {
        assert_eq!(encode_mutf8("a\0b"), b"a\xc0\x80b");
        assert_eq!(encode_mutf8("😀"), [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]);
        assert_eq!(
            droidsaw_dex::mutf8::decode_mutf8(&encode_mutf8("A😀\0Z")).unwrap(),
            "A😀\0Z"
        );
    }

    /// Verbatim transcription of the width match that `OPCODE_UNITS` replaced.
    fn instruction_units_reference(opcode: u8) -> Result<usize> {
        Ok(match opcode {
            0x01
            | 0x04
            | 0x07
            | 0x0a..=0x12
            | 0x1d
            | 0x1e
            | 0x21
            | 0x27
            | 0x28
            | 0x7b..=0x8f
            | 0xb0..=0xcf => 1,
            0x02
            | 0x05
            | 0x08
            | 0x13
            | 0x15
            | 0x16
            | 0x19
            | 0x1a
            | 0x1c
            | 0x1f
            | 0x20
            | 0x22
            | 0x23
            | 0x29
            | 0x2d..=0x3d
            | 0x44..=0x6d
            | 0x90..=0xaf
            | 0xd0..=0xe2
            | 0xfe
            | 0xff => 2,
            0x03
            | 0x06
            | 0x09
            | 0x14
            | 0x17
            | 0x1b
            | 0x24..=0x26
            | 0x2a..=0x2c
            | 0x6e..=0x72
            | 0x74..=0x78
            | 0xfc
            | 0xfd => 3,
            0xfa | 0xfb => 4,
            0x18 => 5,
            _ => bail!("unsupported opcode 0x{opcode:02x}"),
        })
    }

    #[test]
    fn opcode_width_table_agrees_with_the_original_match() {
        for opcode in 1..=u8::MAX {
            match instruction_units_reference(opcode) {
                Ok(width) => assert_eq!(OPCODE_UNITS[opcode as usize] as usize, width, "0x{opcode:02x}"),
                Err(_) => assert_eq!(OPCODE_UNITS[opcode as usize], 0, "0x{opcode:02x}"),
            }
        }
    }

    #[test]
    fn opcode_width_table_agrees_with_the_runtime_path() {
        for opcode in 0..=u8::MAX {
            let code = [opcode, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let width = OPCODE_UNITS[opcode as usize] as usize;
            if opcode == 0 {
                assert_eq!(width, 0, "payloads must use the runtime path");
            } else if width == 0 {
                assert!(instruction_units(&code, 0).is_err(), "0x{opcode:02x} should be rejected");
            } else {
                assert_eq!(instruction_units(&code, 0).unwrap(), width, "0x{opcode:02x}");
            }
        }
    }

    /// Reference transcription of the filter the table replaced.
    fn opcode_matches_reference(kind: RefKind, opcode: u8) -> bool {
        match kind {
            RefKind::String => matches!(opcode, 0x1a | 0x1b),
            RefKind::Type => matches!(opcode, 0x1c | 0x1f | 0x20 | 0x22..=0x25),
            RefKind::Field => matches!(opcode, 0x52..=0x6d),
            RefKind::Method => matches!(opcode, 0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb),
        }
    }

    #[test]
    fn opcode_kind_table_agrees_with_the_old_filter() {
        for opcode in 0..=u8::MAX {
            for kind in [RefKind::String, RefKind::Type, RefKind::Method, RefKind::Field] {
                assert_eq!(
                    OPCODE_KINDS[opcode as usize] & kind.bit() != 0,
                    opcode_matches_reference(kind, opcode),
                    "0x{opcode:02x} {kind:?}"
                );
            }
        }
    }

    #[test]
    fn pair_filter_finds_matches_at_both_edges() {
        assert!(contains_pair(b"\x1a\x05", [0x1a, 0x05]));
        assert!(contains_pair(b"\x00\x1a\x05\x00", [0x1a, 0x05]));
        assert!(contains_pair(b"\x05\x1a", [0x1a, 0x05]));
        assert!(!contains_pair(b"\x1a\x00\x05", [0x1a, 0x05]));
        assert!(!contains_pair(b"", [0x1a, 0x05]));
        assert!(!contains_pair(b"\x1a", [0x1a, 0x05]));
    }

    #[test]
    fn byte_filter_matches_the_unfiltered_scan() {
        let data = const_string_fixture(PARALLEL_SCAN_CLASSES);
        let dex = Dex::parse(&data).unwrap();
        let (kind, targets) = dex
            .resolve_targets(&Query::String("Authorization".to_owned()))
            .unwrap();
        let targets = Targets::new(targets);
        assert!(targets.bytes.is_some(), "one target must stay filterable");
        let filtered = dex.scan_all_classes(kind, &targets).unwrap();
        let unfiltered = Targets {
            indices: targets.indices.clone(),
            bytes: None,
        };
        assert_eq!(filtered, dex.scan_all_classes(kind, &unfiltered).unwrap());
        assert_eq!(filtered.len(), PARALLEL_SCAN_CLASSES);
    }

    #[test]
    fn opcode_widths_cover_reference_instructions() {
        for (opcode, width) in [(0x1a, 2), (0x1b, 3), (0x52, 2), (0x6e, 3), (0xfa, 4)] {
            let code = [opcode, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(instruction_units(&code, 0).unwrap(), width);
        }
    }

    #[test]
    fn payload_widths_are_computed() {
        assert_eq!(
            instruction_units(&[0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0).unwrap(),
            8
        );
        assert_eq!(
            instruction_units(&[0, 3, 1, 0, 3, 0, 0, 0, 1, 2, 3, 0], 0).unwrap(),
            6
        );
    }
}
