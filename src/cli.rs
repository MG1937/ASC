use crate::query::{ClassQuery, MemberQuery, Query, format_class_name, fuzzy_class_pattern};
use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "rasc", version, about = "Native Rust APK and DEX analysis CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Locate a class in an APK and decompile it.
    Getclass(GetClassArgs),
    /// Find code references across every DEX in an APK.
    Findrefs(FindRefsArgs),
    /// Decode and print AndroidManifest.xml from an APK.
    Manifest(ManifestArgs),
    /// List classes defined across every DEX in an APK.
    Classes(ClassesArgs),
}

#[derive(Debug, Args)]
pub struct ClassesArgs {
    #[arg(long, alias = "thread", default_value_t = 8)]
    pub threads: usize,
    /// Case-insensitive substring filter over Java-style class names.
    #[arg(short, long)]
    pub filter: Option<String>,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Print phase timings on stderr.
    #[arg(long)]
    pub debug: bool,
    pub apk_path: PathBuf,
}

#[derive(Debug, Args)]
pub struct ManifestArgs {
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    pub apk_path: PathBuf,
}

#[derive(Debug, Args)]
pub struct GetClassArgs {
    #[arg(long)]
    pub debug: bool,
    #[arg(long, alias = "thread", default_value_t = 8)]
    pub threads: usize,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    pub apk_path: PathBuf,
    pub dalvik_class: String,
}

#[derive(Debug, Args)]
pub struct FindRefsArgs {
    #[arg(long)]
    pub debug: bool,
    #[arg(long, alias = "thread", default_value_t = 8)]
    pub threads: usize,
    pub apk_path: PathBuf,
    #[command(subcommand)]
    pub kind: FindKind,
}

impl FindRefsArgs {
    pub fn query(&self) -> Result<Query> {
        match &self.kind {
            FindKind::String(q) => Ok(Query::String(q.value.clone())),
            FindKind::Type(q) => Ok(Query::Type(q.value.clone())),
            FindKind::Method(q) => Ok(Query::Method(q.member_query("method")?)),
            FindKind::Field(q) => Ok(Query::Field(q.member_query("field")?)),
        }
    }

    pub fn output_path(&self) -> Option<&Path> {
        match &self.kind {
            FindKind::String(q) | FindKind::Type(q) => q.output.as_deref(),
            FindKind::Method(q) | FindKind::Field(q) => q.output.as_deref(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum FindKind {
    String(ValueQuery),
    Type(ValueQuery),
    Method(MemberArgs),
    Field(MemberArgs),
}

#[derive(Debug, Args)]
pub struct ValueQuery {
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    pub value: String,
}

#[derive(Debug, Args)]
pub struct MemberArgs {
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    pub name: Option<String>,
    #[arg(long = "class")]
    pub class_name: Option<String>,
    #[arg(long)]
    pub fuzzy_class: bool,
}

impl MemberArgs {
    fn member_query(&self, kind: &str) -> Result<MemberQuery> {
        let name = self
            .name
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let class = match self.class_name.as_deref().filter(|name| !name.is_empty()) {
            None => None,
            Some(name) if self.fuzzy_class => Some(ClassQuery::Fuzzy(fuzzy_class_pattern(name))),
            Some(name) => Some(ClassQuery::Exact(format_class_name(name)?)),
        };
        if name.is_none() && class.is_none() {
            bail!("{kind} query needs at least one of class or {kind} name");
        }
        Ok(MemberQuery { name, class })
    }
}
