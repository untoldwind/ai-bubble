//! The `hostfs` section of the spec file: what the FUSE filesystem —
//! which is always the sandbox root — exposes of the host.
//!
//! This is only the *config-file* view: [`HostFsConfig::patterns`] and
//! [`HostFsConfig::ops`] compile it down onto the internal [`Patterns`]
//! and [`Op`] types ([`super::internal`]) that the FUSE filesystem and
//! the sandbox itself work with.
//!
//! Environment variables: every path-like mapping field (`glob`, `path`,
//! `src`, `dest`, `source`) may reference environment variables as
//! `${VAR}` (see [`env_string`]). They are expanded while the field is
//! deserialized — before validation and everything downstream — so the
//! rest of the code only ever sees the fully expanded text. Other string
//! fields (the mapping `type` tag, `net.allow`, ...) are never expanded.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use schemars::JsonSchema;

use super::tmpfs::TmpfsPerms;
use crate::{
    hostfs::patterns::{Patterns, Permission},
    spec::internal::Op,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Globs(pub Vec<String>);

impl<'de> Deserialize<'de> for Globs {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Globs;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a glob pattern or a list of glob patterns")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Ok(Globs(vec![super::file::expand_str(s).map_err(E::custom)?]))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut globs = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    globs.push(super::file::expand_str(&s).map_err(serde::de::Error::custom)?);
                }
                Ok(Globs(globs))
            }
        }
        deserializer.deserialize_any(V)
    }
}

impl schemars::JsonSchema for Globs {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Globs".into()
    }

    fn inline_schema() -> bool {
        // Inline the oneOf; the type has no name in the JSON format.
        true
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A glob pattern of absolute host paths (`*`, `?`, `[...]`, `**`), \
                            either as a single string or as a list of them (a list behaves like \
                            separate mappings in the listed order). The list may also be spelled \
                            `globs` instead of `glob`.",
            "oneOf": [
                { "type": "string" },
                { "type": "array", "items": { "type": "string" } },
            ],
        })
    }
}

/// Like [`Globs`], for the single-path-or-list fields (`empty`, `tmpfs`,
/// `session-cache`, `project-cache`): a single absolute path, or a list
/// of them (a list behaves like separate mappings in the listed order).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Paths(pub Vec<String>);

impl<'de> Deserialize<'de> for Paths {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Paths;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an absolute path or a list of them")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Ok(Paths(vec![super::file::expand_str(s).map_err(E::custom)?]))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut paths = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    paths.push(super::file::expand_str(&s).map_err(serde::de::Error::custom)?);
                }
                Ok(Paths(paths))
            }
        }
        deserializer.deserialize_any(V)
    }
}

impl schemars::JsonSchema for Paths {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Paths".into()
    }

    fn inline_schema() -> bool {
        // Inline the oneOf; the type has no name in the JSON format.
        true
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "An absolute path, named exactly (no wildcards), either as a single \
                            string or as a list of them (a list behaves like separate mappings \
                            in the listed order). The list may also be spelled `paths` instead \
                            of `path`.",
            "oneOf": [
                { "type": "string" },
                { "type": "array", "items": { "type": "string" } },
            ],
        })
    }
}

/// The spec's `hostfs.mappings` setting: an *ordered* list of mappings,
/// each selecting host paths for one treatment.
///
/// A `ro`, `rw` or `hide` mapping selects paths with **glob** patterns of
/// absolute host paths — either one (`"glob": "/usr"`) or several
/// (`"globs": ["/usr", "/lib"]`); `empty`, `tmpfs`, `session-cache` and
/// `project-cache` likewise take one absolute path (`"path": "/dev"`) or
/// several (`"paths": ["/tmp", "/var/tmp"]`); every other mapping names
/// one absolute path exactly (it makes no sense to glob a mount point).
/// The `dev` and `proc` mappings default their path to `/dev` and `/proc`.
/// The list order matters: when a path matches several mappings, the
/// **last** matching mapping decides — and the mount ops the mappings
/// generate are applied in mapping order, too. A mapping with several
/// globs (or paths) behaves exactly like separate mappings in the listed
/// order.
///
/// The mount-point mappings (`dev`, `tmpfs`, `proc`, `bind`) are
/// shorthand for an `empty` mapping *plus* the corresponding mount op
/// (see [`Mapping::op`]): the FUSE filesystem exposes the path empty so
/// it can be mounted on, and the sandbox stacks the real mount on top of
/// it. `symlink` is the odd one out: it only produces a symlink op (see
/// [`Mapping::op`]) and does not touch the host filesystem at all.
#[derive(Debug, Clone, PartialEq, JsonSchema)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Mapping {
    /// The matched paths are mirrored **read-only**.
    Ro {
        /// A glob pattern of absolute host paths (`*`, `?`, `[...]`, `**`),
        /// either as a single string or as a list of them (a list behaves
        /// like separate mappings in the listed order). Also accepted
        /// under the alias `globs`.
        glob: Globs,
    },
    /// The matched paths are mirrored **read-write** (as far as the real
    /// host permissions allow).
    Rw {
        /// A glob pattern of absolute host paths (`*`, `?`, `[...]`, `**`),
        /// either as a single string or as a list of them (a list behaves
        /// like separate mappings in the listed order). Also accepted
        /// under the alias `globs`.
        glob: Globs,
    },
    /// The matched paths are hidden (a hidden directory hides its whole
    /// subtree).
    ///
    /// Glob semantics: `**` spans directory levels only as a **whole**
    /// component; inside a longer component (`**secret**`) it degrades to
    /// `*` and matches only direct children of the named directory. Use
    /// `dir/**/*secret*` to hide every entry named `*secret*` anywhere
    /// below `dir`. Matching is case-sensitive.
    Hide {
        /// A glob pattern of absolute host paths (`*`, `?`, `[...]`, `**`),
        /// either as a single string or as a list of them (a list behaves
        /// like separate mappings in the listed order). Also accepted
        /// under the alias `globs`.
        glob: Globs,
    },
    /// The named paths are exposed **empty** — mount points for the
    /// sandbox's ops.
    Empty {
        /// An absolute host path, named exactly (no wildcards) — either
        /// as a single string or as a list of them (a list behaves like
        /// separate mappings in the listed order). Also accepted under
        /// the alias `paths`.
        path: Paths,
    },
    /// Shorthand for `empty` at `path` **plus** a minimal `/dev` mount
    /// (like bwrap's `--dev`) on top of it. `path` defaults to `/dev`.
    Dev {
        /// An absolute host path, named exactly (no wildcards).
        #[serde(default = "default_dev_path")]
        path: String,
    },
    /// Shorthand for `empty` at `path` **plus** a fresh tmpfs (like
    /// bwrap's `--tmpfs`) on top of it — one per named path.
    Tmpfs {
        /// An absolute host path, named exactly (no wildcards) — either
        /// as a single string or as a list of them (each gets its own
        /// tmpfs). Also accepted under the alias `paths`.
        path: Paths,
        /// Octal mode of the tmpfs root, e.g. `"1777"` or `1777`.
        /// Default: `0755`.
        perms: Option<TmpfsPerms>,
        /// Maximum tmpfs size in bytes.
        size: Option<u64>,
    },
    /// Shorthand for `empty` at `path` **plus** a fresh procfs instance
    /// (showing only the sandbox's own processes) on top of it. `path`
    /// defaults to `/proc`.
    Proc {
        /// An absolute host path, named exactly (no wildcards).
        #[serde(default = "default_proc_path")]
        path: String,
    },
    /// Shorthand for `empty` at `dest` **plus** a bind mount of the host
    /// path `src` on top of it. `dest` defaults to `src` — the plain
    /// "bind the real host path at the same path" case. The field is
    /// also accepted under its old name `path` (deprecated alias for
    /// `src`).
    ///
    /// Bind mounts bypass the FUSE mirror entirely: the host path appears
    /// in the sandbox with its real permissions and no pattern-based
    /// write policy. They are therefore mounted **read-only** by default;
    /// set `rw: true` to expose the host path read-write (as far as the
    /// real host permissions allow).
    Bind {
        /// An absolute host path to bind (named exactly, no wildcards).
        /// Also accepted under its old name `path` (deprecated alias,
        /// meaning "bind at the same path").
        #[serde(alias = "path")]
        src: String,
        /// An absolute sandbox path to bind it at. Defaults to `src`.
        #[serde(default)]
        dest: Option<String>,
        /// Whether the bind mount is writable. Defaults to `false`:
        /// bind mounts are read-only unless explicitly asked for.
        #[serde(default)]
        rw: bool,
    },
    /// A **lightweight bind** routed through the host filesystem: the
    /// host file or directory `source` is shown *in the FUSE mirror* at
    /// the sandbox path `dest` — like a bind mount, but no mount at all
    /// happens, so it works without mount privileges and is monitored
    /// (and permission-checked) by the host filesystem like any mirrored
    /// path. A redirected directory shows its whole subtree, redirected
    /// paths may be files or directories. A relative `source` is
    /// resolved relative to the directory the spec file lives in.
    ///
    /// Produces no mount op: the redirect lives entirely in the FUSE
    /// filesystem (see [`Mapping::pattern`]).
    #[serde(rename = "redirect-ro")]
    RedirectRo {
        /// An absolute sandbox path to show the source at (named
        /// exactly, no wildcards).
        dest: String,
        /// The host path to show there; absolute, or relative to the
        /// spec file's directory.
        source: String,
    },
    /// Like [`Mapping::RedirectRo`], but the redirected path is also
    /// writable (as far as the real host permissions allow).
    #[serde(rename = "redirect-rw")]
    RedirectRw {
        /// An absolute sandbox path to show the source at (named
        /// exactly, no wildcards).
        dest: String,
        /// The host path to show there; absolute, or relative to the
        /// spec file's directory.
        source: String,
    },
    /// The named path is backed by a **per-run temporary directory**: a
    /// fresh, empty host directory (created under `/tmp` when the sandbox
    /// starts) is shown at the path — writable, like `redirect-rw`, but
    /// nothing it contains outlives the run. Several `session-cache`
    /// mappings share *one* tmp directory: each path maps onto the tmp
    /// directory plus its own relative sub-path (e.g. `/home/a/.cache` →
    /// `<tmpdir>/home/a/.cache`), so unrelated cache directories never
    /// collide. The tmp directory is wiped once ai-bubble terminates (see
    /// [`HostFsConfig::prepare_caches`] and
    /// `crate::hostfs::set_session_cache_root`).
    ///
    /// Purely a FUSE redirect (see [`Mapping::op`]); the mapping is
    /// rewritten into a `redirect-rw` at startup — [`Mapping::SessionCache`]
    /// mappings only exist in the unresolved config view.
    #[serde(rename = "session-cache")]
    SessionCache {
        /// An absolute sandbox path, named exactly (no wildcards) —
        /// either as a single string or as a list of them (a list
        /// behaves like separate mappings in the listed order). Also
        /// accepted under the alias `paths`.
        path: Paths,
    },
    /// Like [`Mapping::SessionCache`], but backed by the **project cache**
    /// instead of a tmp directory: the path maps onto `cache/<path>` below
    /// the directory the spec file lives in (`.ai-bubble/cache/...` by
    /// default), so the content persists across runs — and is shared by
    /// every sandbox using that spec directory.
    #[serde(rename = "project-cache")]
    ProjectCache {
        /// An absolute sandbox path, named exactly (no wildcards) —
        /// either as a single string or as a list of them (a list
        /// behaves like separate mappings in the listed order). Also
        /// accepted under the alias `paths`.
        path: Paths,
    },
    /// Create a symlink at `dest` pointing to `src`, like bwrap's
    /// `--symlink`. `src` is relative to the sandbox root (`usr/lib`,
    /// like bwrap's relative symlink targets) or absolute. This mapping
    /// does not expose anything in the host filesystem — it only
    /// generates the symlink op (applied in mapping order, together with
    /// the other mount ops).
    Symlink {
        /// The symlink target, relative to the sandbox root (or absolute).
        src: String,
        /// An absolute sandbox path for the new symlink.
        dest: String,
    },
    /// Show a **purely virtual, in-memory file** at the path: `content`
    /// (a small file, e.g. an `/etc/resolv.conf`) is served from the
    /// mirror's memory — the host filesystem is not consulted at all,
    /// and the file leaves no trace on the host. The injected file is
    /// read-only and nothing below its path is visible. Like the
    /// redirects, this is purely a FUSE feature (see
    /// [`Mapping::pattern`]): it produces no op.
    Inject {
        /// An absolute sandbox path for the injected file (named
        /// exactly, no wildcards).
        path: String,
        /// The content of the injected file (text, served as UTF-8).
        content: String,
    },
}

/// The default path of the `dev` mapping's mount point.
fn default_dev_path() -> String {
    "/dev".to_string()
}

/// The default path of the `proc` mapping's mount point.
fn default_proc_path() -> String {
    "/proc".to_string()
}

/// The mapping as it is written in the spec file, before validation.
///
/// Every path-like field uses [`env_string`] as its deserializer, so
/// `${VAR}` environment references are expanded while the field is read
/// (before the `TryFrom` validation below sees it). The `ro`/`rw`/`hide`
/// globs expand inside [`Globs`], which also accepts a list of them.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum UncheckedMapping {
    Ro {
        #[serde(alias = "globs")]
        glob: Globs,
    },
    Rw {
        #[serde(alias = "globs")]
        glob: Globs,
    },
    Hide {
        #[serde(alias = "globs")]
        glob: Globs,
    },
    Empty {
        #[serde(alias = "paths")]
        path: Paths,
    },
    Dev {
        #[serde(default = "default_dev_path", deserialize_with = "env_string")]
        path: String,
    },
    Tmpfs {
        #[serde(alias = "paths")]
        path: Paths,
        perms: Option<TmpfsPerms>,
        size: Option<u64>,
    },
    Proc {
        #[serde(default = "default_proc_path", deserialize_with = "env_string")]
        path: String,
    },
    Bind {
        #[serde(alias = "path", deserialize_with = "env_string")]
        src: String,
        #[serde(default, deserialize_with = "env_opt_string")]
        dest: Option<String>,
        rw: Option<bool>,
    },
    #[serde(rename = "redirect-ro")]
    RedirectRo {
        #[serde(deserialize_with = "env_string")]
        dest: String,
        #[serde(deserialize_with = "env_string")]
        source: String,
    },
    #[serde(rename = "redirect-rw")]
    RedirectRw {
        #[serde(deserialize_with = "env_string")]
        dest: String,
        #[serde(deserialize_with = "env_string")]
        source: String,
    },
    #[serde(rename = "session-cache")]
    SessionCache {
        #[serde(alias = "paths")]
        path: Paths,
    },
    #[serde(rename = "project-cache")]
    ProjectCache {
        #[serde(alias = "paths")]
        path: Paths,
    },
    Symlink {
        #[serde(deserialize_with = "env_string")]
        src: String,
        #[serde(deserialize_with = "env_string")]
        dest: String,
    },
    Inject {
        #[serde(deserialize_with = "env_string")]
        path: String,
        content: String,
    },
}

/// Deserialize a path-like mapping field with `${VAR}` environment
/// expansion (see [`super::file::expand_str`]): the field is read as a
/// plain string, then the references are resolved — before validation
/// and everything downstream sees it. Only the path-like fields of the
/// mappings use this; other string fields (`net.allow`, ...) are never
/// expanded. An unset variable is a deserialization error.
fn env_string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let raw = String::deserialize(deserializer)?;
    super::file::expand_str(&raw).map_err(serde::de::Error::custom)
}

/// Like [`env_string`], for `Option<String>` fields.
fn env_opt_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    env_string(deserializer).map(Some)
}

/// Warn when a glob uses `**` *inside* a path component (e.g.
/// `${PWD}/**secret**`): the matcher collapses it to a single `*`, which
/// never crosses `/`, so such a rule only matches **direct children** of
/// the named directory — everything deeper is unprotected. Spanning
/// directory levels requires `**` as a whole component:
/// `dir/**/*secret*` matches any path below `dir` whose name contains
/// `secret`. (Matching is also case-sensitive; spell alternatives like
/// `*[Ss]ecret*` explicitly.)
fn warn_embedded_double_star(kind: &str, glob: &str) {
    if glob
        .split('/')
        .filter(|c| !c.is_empty())
        .any(|c| c.contains("**") && c != "**")
    {
        eprintln!(
            "ai-bubble: hostfs {kind} mapping: glob {glob:?} has `**` inside a path component, \
             where it acts like `*` (it does not cross `/`); use `dir/**/part` to span levels"
        );
    }
}

impl TryFrom<UncheckedMapping> for Mapping {
    type Error = String;

    fn try_from(raw: UncheckedMapping) -> Result<Self, Self::Error> {
        fn absolute(kind: &str, field: &str, value: String) -> Result<String, String> {
            if value.starts_with('/') {
                Ok(value)
            } else {
                Err(format!(
                    "hostfs {kind} mapping: {field} {value:?} is not an absolute path"
                ))
            }
        }
        fn nonempty(kind: &str, field: &str, value: String) -> Result<String, String> {
            if value.is_empty() {
                Err(format!("hostfs {kind} mapping: {field} must not be empty"))
            } else {
                Ok(value)
            }
        }
        /// A redirect destination: absolute, wildcard-free (a redirect maps
        /// one specific path; wildcards could not be resolved onto a
        /// single source anyway), and free of `..` components (a `..`
        /// would let a cache mapping's relative sub-path escape the cache
        /// root onto an arbitrary host directory — see `sub_path`).
        fn redirect_dest(kind: &str, field: &str, value: String) -> Result<String, String> {
            let dest = absolute(kind, field, value)?;
            if dest.contains(['*', '?', '[']) {
                Err(format!(
                    "hostfs {kind} mapping: dest {dest:?} must not contain wildcards"
                ))
            } else if Path::new(&dest)
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                Err(format!(
                    "hostfs {kind} mapping: dest {dest:?} must not contain '..'"
                ))
            } else {
                Ok(dest)
            }
        }
        /// A set of glob patterns, all of which must be absolute.
        fn absolute_globs(kind: &str, globs: Globs) -> Result<Globs, String> {
            globs
                .0
                .into_iter()
                .map(|g| absolute(kind, "glob", g))
                .collect::<Result<Vec<_>, _>>()
                .map(Globs)
        }
        /// A set of paths, all of which must be absolute.
        fn absolute_paths(kind: &str, paths: Paths) -> Result<Paths, String> {
            paths
                .0
                .into_iter()
                .map(|p| absolute(kind, "path", p))
                .collect::<Result<Vec<_>, _>>()
                .map(Paths)
        }
        /// A set of redirect destinations, all of which must be absolute
        /// and wildcard-free (see `redirect_dest`).
        fn redirect_dests(kind: &str, paths: Paths) -> Result<Paths, String> {
            paths
                .0
                .into_iter()
                .map(|p| redirect_dest(kind, "path", p))
                .collect::<Result<Vec<_>, _>>()
                .map(Paths)
        }
        Ok(match raw {
            UncheckedMapping::Ro { glob } => Mapping::Ro {
                glob: absolute_globs("ro", glob)?,
            },
            UncheckedMapping::Rw { glob } => Mapping::Rw {
                glob: absolute_globs("rw", glob)?,
            },
            UncheckedMapping::Hide { glob } => {
                for g in &glob.0 {
                    warn_embedded_double_star("hide", g);
                }
                Mapping::Hide {
                    glob: absolute_globs("hide", glob)?,
                }
            }
            UncheckedMapping::Empty { path } => Mapping::Empty {
                path: absolute_paths("empty", path)?,
            },
            UncheckedMapping::Dev { path } => Mapping::Dev {
                path: absolute("dev", "path", path)?,
            },
            UncheckedMapping::Tmpfs { path, perms, size } => Mapping::Tmpfs {
                path: absolute_paths("tmpfs", path)?,
                perms,
                size,
            },
            UncheckedMapping::Proc { path } => Mapping::Proc {
                path: absolute("proc", "path", path)?,
            },
            UncheckedMapping::Bind { src, dest, rw } => Mapping::Bind {
                src: absolute("bind", "src", src)?,
                dest: match dest {
                    Some(dest) => Some(absolute("bind", "dest", dest)?),
                    None => None,
                },
                rw: rw.unwrap_or(false),
            },
            UncheckedMapping::RedirectRo { dest, source } => Mapping::RedirectRo {
                dest: redirect_dest("redirect-ro", "dest", dest)?,
                source: nonempty("redirect-ro", "source", source)?,
            },
            UncheckedMapping::RedirectRw { dest, source } => Mapping::RedirectRw {
                dest: redirect_dest("redirect-rw", "dest", dest)?,
                source: nonempty("redirect-rw", "source", source)?,
            },
            UncheckedMapping::SessionCache { path } => Mapping::SessionCache {
                path: redirect_dests("session-cache", path)?,
            },
            UncheckedMapping::ProjectCache { path } => Mapping::ProjectCache {
                path: redirect_dests("project-cache", path)?,
            },
            UncheckedMapping::Symlink { src, dest } => Mapping::Symlink {
                src: nonempty("symlink", "src", src)?,
                dest: absolute("symlink", "dest", dest)?,
            },
            UncheckedMapping::Inject { path, content } => Mapping::Inject {
                path: redirect_dest("inject", "path", path)?,
                content: nonempty("inject", "content", content)?,
            },
        })
    }
}

impl<'de> Deserialize<'de> for Mapping {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        UncheckedMapping::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for Mapping {
    /// The mapping as the same JSON object shape the spec file uses, so
    /// the runtime-control protocol (`policy-get`'s `fs` domain and the
    /// `fs-set` update frames) round-trips losslessly: the deserializer
    /// accepts exactly these objects (plus its deprecated aliases, which
    /// serialization never produces). Field names, the `"type"` tag and
    /// the `redirect-*` renames mirror [`UncheckedMapping`].
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let (tag, fields): (&str, Vec<(&str, serde_json::Value)>) = match self {
            Mapping::Ro { glob } => (
                "ro",
                vec![(
                    "glob",
                    serde_json::to_value(glob).map_err(serde::ser::Error::custom)?,
                )],
            ),
            Mapping::Rw { glob } => (
                "rw",
                vec![(
                    "glob",
                    serde_json::to_value(glob).map_err(serde::ser::Error::custom)?,
                )],
            ),
            Mapping::Hide { glob } => (
                "hide",
                vec![(
                    "glob",
                    serde_json::to_value(glob).map_err(serde::ser::Error::custom)?,
                )],
            ),
            Mapping::Empty { path } => (
                "empty",
                vec![(
                    "path",
                    serde_json::to_value(path).map_err(serde::ser::Error::custom)?,
                )],
            ),
            Mapping::Dev { path } => ("dev", vec![("path", serde_json::Value::from(path.clone()))]),
            Mapping::Tmpfs { path, perms, size } => ("tmpfs", {
                let mut fields = vec![(
                    "path",
                    serde_json::to_value(path).map_err(serde::ser::Error::custom)?,
                )];
                if let Some(perms) = perms {
                    fields.push((
                        "perms",
                        serde_json::to_value(perms).map_err(serde::ser::Error::custom)?,
                    ));
                }
                if let Some(size) = size {
                    fields.push(("size", serde_json::Value::from(*size)));
                }
                fields
            }),
            Mapping::Proc { path } => (
                "proc",
                vec![("path", serde_json::Value::from(path.clone()))],
            ),
            Mapping::Bind { src, dest, rw } => {
                let mut fields = vec![("src", serde_json::Value::from(src.clone()))];
                if let Some(dest) = dest {
                    fields.push(("dest", serde_json::Value::from(dest.clone())));
                }
                fields.push(("rw", serde_json::Value::from(*rw)));
                ("bind", fields)
            }
            Mapping::RedirectRo { dest, source } => (
                "redirect-ro",
                vec![
                    ("dest", serde_json::Value::from(dest.clone())),
                    ("source", serde_json::Value::from(source.clone())),
                ],
            ),
            Mapping::RedirectRw { dest, source } => (
                "redirect-rw",
                vec![
                    ("dest", serde_json::Value::from(dest.clone())),
                    ("source", serde_json::Value::from(source.clone())),
                ],
            ),
            // Session/project caches only exist in the *unresolved* config
            // view; `prepare_caches` rewrites them into `redirect-rw` before
            // the run starts (and the control plane rejects them in `fs-set`).
            Mapping::SessionCache { path } => (
                "session-cache",
                vec![(
                    "path",
                    serde_json::to_value(path).map_err(serde::ser::Error::custom)?,
                )],
            ),
            Mapping::ProjectCache { path } => (
                "project-cache",
                vec![(
                    "path",
                    serde_json::to_value(path).map_err(serde::ser::Error::custom)?,
                )],
            ),
            Mapping::Symlink { src, dest } => (
                "symlink",
                vec![
                    ("src", serde_json::Value::from(src.clone())),
                    ("dest", serde_json::Value::from(dest.clone())),
                ],
            ),
            Mapping::Inject { path, content } => (
                "inject",
                vec![
                    ("path", serde_json::Value::from(path.clone())),
                    ("content", serde_json::Value::from(content.clone())),
                ],
            ),
        };
        let mut map = serializer.serialize_map(Some(1 + fields.len()))?;
        map.serialize_entry("type", tag)?;
        for (key, value) in fields {
            map.serialize_entry(key, &value)?;
        }
        map.end()
    }
}

/// Compile a mapping list into the pattern set it expresses — the
/// fallible counterpart of [`HostFsConfig::patterns`], used by the
/// runtime-control plane (`fs-set`): a bad glob or an inapplicable
/// mapping must be reported to the control client instead of killing
/// the FUSE server (which [`Patterns::new`] would do).
///
/// Two mappings are rejected here that the spec loader accepts only in
/// their *preprocessed* form: the cache mappings (the loader rewrites
/// them into `redirect-rw` with a resolved backing directory) and
/// redirects with a relative `source` (the loader resolves those against
/// the spec directory) — a control client must send the resolved shapes.
pub fn patterns_from_mappings(mappings: &[Mapping]) -> Result<Patterns, String> {
    let mut pairs: Vec<(String, Permission)> = Vec::new();
    for mapping in mappings {
        match mapping {
            Mapping::SessionCache { .. } | Mapping::ProjectCache { .. } => {
                return Err(
                    "session-cache/project-cache mappings must be resolved by the spec loader; \
                     use redirect-rw with an absolute backing directory"
                        .into(),
                );
            }
            Mapping::RedirectRo { source, .. } | Mapping::RedirectRw { source, .. }
                if !Path::new(source).is_absolute() =>
            {
                return Err(format!(
                    "redirect source {source:?} is relative; resolve it against the \
                     spec directory before sending it to fs-set"
                ));
            }
            _ => {}
        }
        for pattern in mapping.pattern() {
            pairs.push((pattern.to_string(), mapping.permission()));
        }
    }
    Patterns::try_new(pairs)
}

impl Mapping {
    /// The hostfs glob pattern(s) the mapping selects paths with, if it
    /// touches the host filesystem at all. The mount-point mappings
    /// (`empty`, `dev`, `tmpfs`, `proc`, `bind`) name their paths as
    /// wildcard-free "patterns"; a `symlink` mapping exposes
    /// nothing. A multi-path mapping (or multi-glob) yields its paths
    /// in listed order — exactly like separate mappings.
    fn pattern(&self) -> Vec<&str> {
        match self {
            Mapping::Ro { glob } | Mapping::Rw { glob } | Mapping::Hide { glob } => {
                glob.0.iter().map(String::as_str).collect()
            }
            Mapping::Empty { path } | Mapping::Tmpfs { path, .. } => {
                path.0.iter().map(String::as_str).collect()
            }
            Mapping::Dev { path } | Mapping::Proc { path } => vec![path],
            Mapping::Bind { src, dest, .. } => vec![dest.as_deref().unwrap_or(src)],
            Mapping::RedirectRo { dest, .. } | Mapping::RedirectRw { dest, .. } => vec![dest],
            Mapping::SessionCache { path } | Mapping::ProjectCache { path } => {
                path.0.iter().map(String::as_str).collect()
            }
            Mapping::Inject { path, .. } => vec![path],
            Mapping::Symlink { .. } => vec![],
        }
    }

    /// One-line human description of the mapping: its permission/action
    /// and the paths it selects or mounts. Used by `ai-bubble ls`.
    pub fn describe(&self) -> String {
        match self {
            Mapping::Ro { glob } => format!("ro     {}", glob.0.join(", ")),
            Mapping::Rw { glob } => format!("rw     {}", glob.0.join(", ")),
            Mapping::Hide { glob } => format!("hide   {}", glob.0.join(", ")),
            Mapping::Empty { path } => format!("empty  {}", path.0.join(", ")),
            Mapping::Dev { path } => format!("dev    {path}"),
            Mapping::Tmpfs { path, .. } => format!("tmpfs  {}", path.0.join(", ")),
            Mapping::Proc { path } => format!("proc   {path}"),
            Mapping::Bind { src, dest, rw } => match (rw, dest) {
                (false, Some(dest)) => format!("bind-ro {src} -> {dest}"),
                (false, None) => format!("bind-ro {src}"),
                (true, Some(dest)) => format!("bind-rw {src} -> {dest}"),
                (true, None) => format!("bind-rw {src}"),
            },
            Mapping::RedirectRo { dest, source } => {
                format!("redirect-ro {source} -> {dest}")
            }
            Mapping::RedirectRw { dest, source } => {
                format!("redirect-rw {source} -> {dest}")
            }
            Mapping::SessionCache { path } => format!("session-cache {}", path.0.join(", ")),
            Mapping::ProjectCache { path } => format!("project-cache {}", path.0.join(", ")),
            Mapping::Symlink { src, dest } => format!("symlink {dest} -> {src}"),
            Mapping::Inject { path, content } => format!("inject {path} ({} bytes)", content.len()),
        }
    }

    /// The internal permission the mapping expresses. Every mount-point
    /// mapping exposes its path empty, like [`Mapping::Empty`]; the
    /// redirect mappings carry their `source` as a
    /// [`Permission::Redirect`] parameter.
    fn permission(&self) -> Permission {
        match self {
            Mapping::Ro { .. } => Permission::Ro,
            Mapping::Rw { .. } => Permission::Rw,
            Mapping::Hide { .. } => Permission::Hide,
            Mapping::RedirectRo { source, .. } => Permission::Redirect {
                source: PathBuf::from(source),
                writable: false,
            },
            Mapping::RedirectRw { source, .. } => Permission::Redirect {
                source: PathBuf::from(source),
                writable: true,
            },
            Mapping::Inject { content, .. } => Permission::Inject {
                content: content.clone(),
            },
            Mapping::SessionCache { .. } | Mapping::ProjectCache { .. } => {
                // A cache mapping *is* a redirect-rw — to its backing
                // directory. The real source is filled in by
                // [`HostFsConfig::prepare_caches`] (which rewrites the
                // mapping into a `redirect-rw`); only `ai-bubble ls` ever
                // sees mappings in this unresolved state, where the empty
                // source just means "writable redirect, target not shown".
                Permission::Redirect {
                    source: PathBuf::new(),
                    writable: true,
                }
            }
            _ => Permission::Empty,
        }
    }
    /// The ops the mapping stands for, if any. The mount-point mappings
    /// (`dev`, `tmpfs`, `proc`, `bind`) produce the op that is stacked on
    /// top of the empty path they expose — one per path for a multi-path
    /// mapping — and `symlink` produces the symlink op; every other
    /// mapping — including the redirects, which live entirely inside the
    /// FUSE filesystem — produces none.
    pub fn op(&self) -> Vec<Op> {
        match self {
            Mapping::Dev { path } => vec![Op::Dev {
                dest: PathBuf::from(path),
            }],
            Mapping::Tmpfs { path, perms, size } => path
                .0
                .iter()
                .map(|p| Op::Tmpfs {
                    dest: PathBuf::from(p),
                    perms: *perms,
                    size: *size,
                })
                .collect(),
            Mapping::Proc { path } => vec![Op::Proc {
                dest: PathBuf::from(path),
            }],
            Mapping::Bind { src, dest, rw } => vec![Op::Bind {
                src: src.clone(),
                dest: PathBuf::from(dest.as_deref().unwrap_or(src)),
                rw: *rw,
            }],
            Mapping::Symlink { src, dest } => vec![Op::Symlink {
                src: src.clone(),
                dest: PathBuf::from(dest),
            }],
            _ => vec![],
        }
    }
}

/// The spec file's `hostfs` section: what the FUSE filesystem — which is
/// always the sandbox root — exposes of the host.
#[derive(Debug, Default, PartialEq, Deserialize, Clone, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HostFsConfig {
    /// An ordered list of mappings. `ro`, `rw` and `hide` select paths
    /// with glob patterns (`glob`: a string or a list of strings — the
    /// list also spellable `globs`) of absolute host paths: matched paths
    /// are mirrored into the sandbox — read-only (`ro`) or read-write
    /// (`rw`, as far as the underlying host permissions allow) — or
    /// hidden (`hide`). `empty`, `tmpfs`, `session-cache` and
    /// `project-cache` likewise take one absolute path (`path`) or
    /// several (`paths`): `empty` exposes it empty (an empty, unwritable
    /// directory, or an empty file when the path matches a real file),
    /// `tmpfs` stacks a fresh tmpfs on it, and the cache mappings back it
    /// with a session or project cache. Order matters — when a path
    /// matches several mappings, the **last** matching mapping decides,
    /// and the mount/symlink ops the mappings generate are applied in
    /// mapping order. Matched paths appear at the same absolute path
    /// inside the sandbox (`/etc/passwd` → `/etc/passwd`); matched
    /// directories are mirrored recursively (or, when hidden, disappear
    /// with their whole subtree). Nothing below an empty path is visible,
    /// and empty paths are shown even when a mirror mapping (or the real
    /// host path) covers them. Missing or empty mappings expose nothing.
    pub mappings: Vec<Mapping>,
}

impl HostFsConfig {
    /// The internal pattern → permission list, in spec order. The
    /// mount-point mappings (`dev`, `tmpfs`, `proc`, `bind`) contribute
    /// an `empty` pattern for their path, exactly like [`Mapping::Empty`];
    /// the redirect mappings contribute their `dest` with a
    /// [`Permission::Redirect`] permission; `symlink` mappings contribute
    /// nothing (they touch only the sandbox root, not the host
    /// filesystem). A multi-glob mapping contributes one entry per glob,
    /// in listed order — exactly like separate mappings.
    pub fn patterns(&self) -> Patterns {
        Patterns::new(
            self.mappings
                .iter()
                .flat_map(|m| {
                    m.pattern()
                        .into_iter()
                        .map(move |p| (p.to_string(), m.permission()))
                })
                .collect(),
        )
    }

    /// The ops the mappings stand for, in mapping order (only the
    /// mount-point and symlink mappings contribute — see [`Mapping::op`]).
    pub fn ops(&self) -> Vec<Op> {
        self.mappings.iter().flat_map(Mapping::op).collect()
    }

    /// Resolve relative redirect `source`s against `spec_dir` (the
    /// directory the spec file lives in). Called by [`Spec::load`]
    /// (see [`super::file::Spec`]); sources that are already absolute
    /// are left alone.
    pub(crate) fn resolve_relative_sources(&mut self, spec_dir: &Path) {
        // The spec dir itself may be relative (e.g. the default
        // `.ai-bubble`): resolve it against the current directory first,
        // so the redirect sources end up unambiguous.
        let dir = std::fs::canonicalize(spec_dir).unwrap_or_else(|_| spec_dir.to_path_buf());
        for mapping in &mut self.mappings {
            let source = match mapping {
                Mapping::RedirectRo { source, .. } | Mapping::RedirectRw { source, .. } => source,
                _ => continue,
            };
            if !source.starts_with('/') {
                let resolved = dir.join(&*source);
                // Clean up `./` and `../` components for the error and
                // `ls` output.
                if let Ok(cleaned) = resolved.canonicalize() {
                    *source = cleaned.to_string_lossy().into_owned();
                } else {
                    *source = resolved.to_string_lossy().into_owned();
                }
            }
        }
    }

    /// Resolve the cache mappings (`session-cache`, `project-cache`) into
    /// plain `redirect-rw` mappings against their backing directories,
    /// which are created here (empty, when new).
    ///
    /// A cache mapping names one or more absolute sandbox paths, each of
    /// which maps onto a **relative sub-path** of a shared cache root —
    /// so several cache mappings (and paths) can share one backing
    /// directory:
    ///
    /// * `session-cache`: the per-run tmp directory `session_root`
    ///   (created by the caller, e.g. `crate::hostfs::new_session_cache_dir`;
    ///   that caller also arms the wipe at termination).
    /// * `project-cache`: the `cache` directory inside the spec directory
    ///   (`spec_dir/cache/<path>`); it persists across runs.
    ///
    /// A mapping with several paths is rewritten into one `redirect-rw`
    /// per path, in the listed order — exactly like separate mappings.
    ///
    /// Returns without changing anything when there are no cache mappings.
    /// Called by `ai-bubble run` (never by `ls`, which only shows the
    /// unresolved mappings).
    pub fn prepare_caches(&mut self, spec_dir: &Path, session_root: Option<&Path>) {
        // The spec dir itself may be relative (e.g. the default
        // `.ai-bubble`): resolve it against the current directory first,
        // like `resolve_relative_sources` does.
        let dir = std::fs::canonicalize(spec_dir).unwrap_or_else(|_| spec_dir.to_path_buf());
        /// One cache mapping expanded to its per-path redirect, or a
        /// non-cache mapping passed through untouched.
        enum Resolved {
            Mapping(Mapping),
            Cache { dest: String, source: PathBuf },
        }
        self.mappings = self
            .mappings
            .iter()
            .flat_map(|mapping| match mapping {
                Mapping::SessionCache { path } => path
                    .0
                    .iter()
                    .map(|p| Resolved::Cache {
                        dest: p.clone(),
                        source: session_root
                            .expect("session root provided whenever session-cache mappings exist")
                            .join(sub_path(p)),
                    })
                    .collect::<Vec<_>>(),
                Mapping::ProjectCache { path } => path
                    .0
                    .iter()
                    .map(|p| Resolved::Cache {
                        dest: p.clone(),
                        source: dir.join("cache").join(sub_path(p)),
                    })
                    .collect::<Vec<_>>(),
                other => vec![Resolved::Mapping(other.clone())],
            })
            .map(|resolved| match resolved {
                Resolved::Mapping(mapping) => mapping,
                Resolved::Cache { dest, source } => {
                    if let Err(e) = std::fs::create_dir_all(&source) {
                        crate::sandbox::die(&format!(
                            "Can't create cache directory {}: {e}",
                            source.display()
                        ));
                    }
                    Mapping::RedirectRw {
                        dest,
                        source: source.to_string_lossy().into_owned(),
                    }
                }
            })
            .collect();
    }

    /// Whether any `session-cache` mapping needs a per-run tmp directory
    /// (see [`HostFsConfig::prepare_caches`]).
    pub fn has_session_caches(&self) -> bool {
        self.mappings
            .iter()
            .any(|m| matches!(m, Mapping::SessionCache { .. }))
    }
}

/// The cache mapping's path (an absolute sandbox path) as the relative
/// sub-path it maps onto inside the shared cache root. Validation
/// ([`Mapping`]'s deserializer) guarantees the path is absolute and free
/// of `..` components, so the result always stays inside the cache root.
fn sub_path(path: &str) -> PathBuf {
    Path::new(path)
        .strip_prefix("/")
        .unwrap_or_else(|_| Path::new(path))
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::super::internal::SandboxConfig;
    use super::super::tests::parse;
    use super::*;

    #[test]
    fn hostfs_mappings_parse() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "ro", "glob": "/etc/*.conf" },
                { "type": "rw", "glob": "/home/me/project" }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns::new(vec![
                ("/etc/*.conf".to_string(), Permission::Ro),
                ("/home/me/project".to_string(), Permission::Rw)
            ])
        );
    }

    #[test]
    fn hostfs_mappings_preserve_order_and_permissions() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "rw", "glob": "/etc" },
                { "type": "hide", "glob": "/etc/passwd" },
                { "type": "empty", "path": "/dev" }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns::new(vec![
                ("/etc".to_string(), Permission::Rw),
                ("/etc/passwd".to_string(), Permission::Hide),
                ("/dev".to_string(), Permission::Empty)
            ])
        );
    }

    #[test]
    fn glob_mappings_accept_a_list_of_globs() {
        // A list of globs behaves exactly like separate mappings in the
        // listed order — under both spellings, `globs` and `glob`.
        let spec = parse(
            r#"{ "hostfs": { "mappings": [ { "type": "ro", "globs": ["/usr", "/lib"] } ] } }"#,
        );
        let separate = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "ro", "glob": "/usr" },
                { "type": "ro", "glob": "/lib" }
            ] } }"#,
        );
        assert_eq!(spec.hostfs.patterns(), separate.hostfs.patterns());
        assert_eq!(spec.hostfs.mappings[0].describe(), "ro     /usr, /lib");
        // The field name is `glob`; the list form may also be spelled
        // `globs`.
        assert_eq!(
            parse(
                r#"{ "hostfs": { "mappings": [ { "type": "ro", "glob": ["/usr", "/lib"] } ] } }"#
            )
            .hostfs
            .patterns(),
            spec.hostfs.patterns()
        );
        // Every glob in the list is expanded and validated like a single
        // one — a relative pattern is rejected.
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "ro", "globs": ["/usr", "lib"] } ] } }"#
            )
            .is_err()
        );
        // Naming the list under both spellings is a duplicate-field error.
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "ro", "glob": "/usr", "globs": ["/usr"] } ] } }"#
            )
            .is_err()
        );
        // Order is preserved within the list: the last matching glob
        // decides, so a later hide shadows an earlier rw.
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "rw", "globs": ["/etc", "/etc/passwd"] },
                { "type": "hide", "glob": "/etc/passwd" }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns::new(vec![
                ("/etc".to_string(), Permission::Rw),
                ("/etc/passwd".to_string(), Permission::Rw),
                ("/etc/passwd".to_string(), Permission::Hide),
            ])
        );
    }

    #[test]
    fn path_mappings_accept_a_list_of_paths() {
        // `empty`, `tmpfs`, `session-cache` and `project-cache` accept a
        // single path or a list of them — a list behaves exactly like
        // separate mappings in the listed order, under both spellings
        // (`paths` and `path`).
        let spec = parse(
            r#"{ "hostfs": { "mappings": [ { "type": "empty", "paths": ["/dev", "/tmp"] } ] } }"#,
        );
        let separate = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "empty", "path": "/dev" },
                { "type": "empty", "path": "/tmp" }
            ] } }"#,
        );
        assert_eq!(spec.hostfs.patterns(), separate.hostfs.patterns());
        assert_eq!(spec.hostfs.mappings[0].describe(), "empty  /dev, /tmp");
        assert_eq!(
            parse(
                r#"{ "hostfs": { "mappings": [ { "type": "empty", "path": ["/dev", "/tmp"] } ] } }"#
            )
            .hostfs
            .patterns(),
            spec.hostfs.patterns()
        );
        // Every path in the list is validated like a single one — a
        // relative or wildcarded path is rejected.
        for mapping in [
            r#"{ "type": "empty", "paths": ["/dev", "tmp"] }"#,
            r#"{ "type": "tmpfs", "paths": ["/tmp", "tmp"] }"#,
            r#"{ "type": "session-cache", "paths": ["/a", "../b"] }"#,
            r#"{ "type": "project-cache", "paths": ["/a", "/b", "/x?[y]"] }"#,
        ] {
            assert!(
                serde_json::from_str::<crate::spec::Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {mapping} ] }} }}"#
                ))
                .is_err(),
                "should reject {mapping}"
            );
        }
        // Naming the list under both spellings is a duplicate-field error.
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "empty", "path": "/dev", "paths": ["/tmp"] } ] } }"#
            )
            .is_err()
        );
        // A multi-path tmpfs produces one op per path, sharing the same
        // perms and size, in the listed order.
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "tmpfs", "paths": ["/tmp", "/var/tmp"], "perms": "1777", "size": 4096 }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.ops(),
            vec![
                Op::Tmpfs {
                    dest: PathBuf::from("/tmp"),
                    perms: Some(TmpfsPerms(0o1777)),
                    size: Some(4096)
                },
                Op::Tmpfs {
                    dest: PathBuf::from("/var/tmp"),
                    perms: Some(TmpfsPerms(0o1777)),
                    size: Some(4096)
                },
            ]
        );
    }

    #[test]
    fn hostfs_mappings_reject_relative_paths_and_bad_types() {
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "ro", "glob": "etc" } ] } }"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "empty", "path": "dev" } ] } }"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "nope", "glob": "/etc" } ] } }"#
            )
            .is_err()
        );
    }

    #[test]
    fn hostfs_mappings_reject_wrong_fields_per_type() {
        // A glob does not make sense for "empty", and "path" not for the
        // mirrored kinds: unknown (or mismatched) fields are rejected.
        for mapping in [
            r#"{ "type": "empty", "path": "/dev", "glob": "/dev" }"#,
            r#"{ "type": "empty", "glob": "/dev" }"#,
            r#"{ "type": "ro", "path": "/etc" }"#,
            r#"{ "type": "rw", "glob": "/etc", "path": "/etc" }"#,
        ] {
            assert!(
                serde_json::from_str::<crate::spec::Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {mapping} ] }} }}"#
                ))
                .is_err(),
                "should reject {mapping}"
            );
        }
    }

    #[test]
    fn hostfs_empty_mappings() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "empty", "path": "/dev" },
                { "type": "empty", "path": "/tmp" }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns::new(vec![
                ("/dev".to_string(), Permission::Empty),
                ("/tmp".to_string(), Permission::Empty)
            ])
        );
        assert!(!parse("{}").hostfs.patterns().has_patterns());
    }

    #[test]
    fn hostfs_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<crate::spec::Spec>(r#"{ "hostfs": { "nope": true } }"#).is_err()
        );
        assert!(
            serde_json::from_str::<crate::spec::Spec>(r#"{ "hostfs": { "root": true } }"#).is_err()
        );
    }

    #[test]
    fn mount_point_mappings_expose_empty_and_produce_ops() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "dev", "path": "/dev" },
                { "type": "tmpfs", "path": "/tmp", "perms": "1777", "size": 1048576 },
                { "type": "tmpfs", "path": "/var/tmp" },
                { "type": "proc", "path": "/proc" },
                { "type": "bind", "src": "/usr" },
                { "type": "bind", "src": "/opt/extra", "dest": "/extra" },
                { "type": "bind", "src": "/var/data", "dest": "/data", "rw": true }
            ] } }"#,
        );
        // The FUSE side sees an empty path for every mount-point mapping,
        // at its sandbox destination.
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns::new(vec![
                ("/dev".to_string(), Permission::Empty),
                ("/tmp".to_string(), Permission::Empty),
                ("/var/tmp".to_string(), Permission::Empty),
                ("/proc".to_string(), Permission::Empty),
                ("/usr".to_string(), Permission::Empty),
                ("/extra".to_string(), Permission::Empty),
                ("/data".to_string(), Permission::Empty),
            ])
        );
        // The sandbox side gets the ops, in mapping order.
        assert_eq!(
            spec.hostfs.ops(),
            vec![
                Op::Dev {
                    dest: PathBuf::from("/dev")
                },
                Op::Tmpfs {
                    dest: PathBuf::from("/tmp"),
                    perms: Some(TmpfsPerms(0o1777)),
                    size: Some(1048576)
                },
                Op::Tmpfs {
                    dest: PathBuf::from("/var/tmp"),
                    perms: None,
                    size: None
                },
                Op::Proc {
                    dest: PathBuf::from("/proc")
                },
                Op::Bind {
                    src: "/usr".to_string(),
                    dest: PathBuf::from("/usr"),
                    rw: false
                },
                Op::Bind {
                    src: "/opt/extra".to_string(),
                    dest: PathBuf::from("/extra"),
                    rw: false
                },
                Op::Bind {
                    src: "/var/data".to_string(),
                    dest: PathBuf::from("/data"),
                    rw: true
                },
            ]
        );
    }

    #[test]
    fn symlink_mapping_produces_only_an_op() {
        // A symlink mapping touches only the sandbox root: it must not
        // contribute anything to the hostfs patterns.
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "bind", "src": "/usr" },
                { "type": "symlink", "src": "usr/lib", "dest": "/lib" },
                { "type": "symlink", "src": "/etc/alternative/sh", "dest": "/bin/sh" }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns::new(vec![("/usr".to_string(), Permission::Empty)])
        );
        assert_eq!(
            spec.hostfs.ops(),
            vec![
                Op::Bind {
                    src: "/usr".to_string(),
                    dest: PathBuf::from("/usr"),
                    rw: false
                },
                Op::Symlink {
                    src: "usr/lib".to_string(),
                    dest: PathBuf::from("/lib")
                },
                Op::Symlink {
                    src: "/etc/alternative/sh".to_string(),
                    dest: PathBuf::from("/bin/sh")
                },
            ]
        );
    }

    #[test]
    fn dev_and_proc_mappings_default_their_path() {
        let spec =
            parse(r#"{ "hostfs": { "mappings": [ { "type": "dev" }, { "type": "proc" } ] } }"#);
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns::new(vec![
                ("/dev".to_string(), Permission::Empty),
                ("/proc".to_string(), Permission::Empty)
            ])
        );
        assert_eq!(
            spec.hostfs.ops(),
            vec![
                Op::Dev {
                    dest: PathBuf::from("/dev")
                },
                Op::Proc {
                    dest: PathBuf::from("/proc")
                }
            ]
        );
    }

    #[test]
    fn inject_mapping_parses_and_is_read_only_virtual_fuse() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "inject", "path": "/etc/resolv.conf", "content": "nameserver 127.0.0.2\n" }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns::new(vec![(
                "/etc/resolv.conf".to_string(),
                Permission::Inject {
                    content: "nameserver 127.0.0.2\n".to_string()
                }
            )])
        );
        // Inject is pure FUSE: no mount op, not writable.
        assert!(spec.hostfs.ops().is_empty());
        assert!(!spec.hostfs.mappings[0].permission().is_writable());
        assert_eq!(
            spec.hostfs.mappings[0].describe(),
            "inject /etc/resolv.conf (21 bytes)"
        );
    }

    #[test]
    fn inject_mapping_rejects_bad_paths_and_empty_content() {
        for mapping in [
            r#"{ "type": "inject", "path": "etc/resolv.conf", "content": "x" }"#,
            r#"{ "type": "inject", "path": "/etc/*", "content": "x" }"#,
            r#"{ "type": "inject", "path": "/../etc/x", "content": "x" }"#,
            r#"{ "type": "inject", "path": "/etc/x" }"#,
            r#"{ "type": "inject", "path": "/etc/x", "content": "" }"#,
            r#"{ "type": "inject", "content": "x" }"#,
            r#"{ "type": "inject", "path": "/etc/x", "content": "x", "glob": "/etc" }"#,
        ] {
            assert!(
                serde_json::from_str::<crate::spec::Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {mapping} ] }} }}"#
                ))
                .is_err(),
                "should reject {mapping}"
            );
        }
    }

    #[test]
    fn cache_mappings_parse_and_prepare_caches_rewrites_them() {
        let dir =
            std::env::temp_dir().join(format!("ai-bubble-spec-caches-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "session-cache", "path": "/home/me/.cache" },
                { "type": "session-cache", "path": "/home/other/.local" },
                { "type": "project-cache", "path": "/home/me/.local" }
            ] } }"#,
        );
        // Before preparation the mappings are pure FUSE (no ops), backed
        // by writable redirects with a not-yet-resolved source.
        assert!(spec.hostfs.ops().is_empty());
        for path in ["/home/me/.cache", "/home/other/.local", "/home/me/.local"] {
            assert!(
                spec.hostfs
                    .patterns()
                    .permission_of(Path::new(path))
                    .is_some_and(|p| p.is_writable())
            );
        }
        assert!(spec.hostfs.has_session_caches());
        assert_eq!(
            spec.hostfs.mappings[0].describe(),
            "session-cache /home/me/.cache"
        );

        let root = crate::hostfs::new_session_cache_dir();
        spec.hostfs.prepare_caches(&dir, Some(&root));
        // Every cache mapping became a redirect-rw against its backing
        // directory, which was created (empty).
        let sources: Vec<_> = spec
            .hostfs
            .mappings
            .iter()
            .map(|m| match m {
                Mapping::RedirectRw { dest, source } => (dest.clone(), PathBuf::from(source)),
                other => panic!("expected a redirect-rw mapping, got {other:?}"),
            })
            .collect();
        assert_eq!(sources[0].0, "/home/me/.cache");
        assert_eq!(sources[1].0, "/home/other/.local");
        assert_eq!(sources[2].0, "/home/me/.local");
        // The two session caches share the same tmp directory, as relative
        // sub-paths.
        assert_eq!(sources[0].1, root.join("home/me/.cache"));
        assert_eq!(sources[1].1, root.join("home/other/.local"));
        // The project cache maps into the spec directory's `cache` folder.
        assert_eq!(
            sources[2].1,
            std::fs::canonicalize(&dir)
                .unwrap()
                .join("cache/home/me/.local")
        );
        // The backing directories exist.
        assert!(sources[0].1.is_dir());
        assert!(sources[1].1.is_dir());
        assert!(sources[2].1.is_dir());
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn prepare_caches_without_cache_mappings_does_nothing() {
        let mut spec =
            parse(r#"{ "hostfs": { "mappings": [ { "type": "rw", "glob": "/etc" } ] } }"#);
        assert!(!spec.hostfs.has_session_caches());
        spec.hostfs
            .prepare_caches(Path::new("/nonexistent-ai-bubble-test"), None);
        assert_eq!(spec.hostfs.mappings.len(), 1);
    }

    #[test]
    fn cache_mappings_reject_bad_paths() {
        for mapping in [
            r#"{ "type": "session-cache", "path": "home/.cache" }"#,
            r#"{ "type": "session-cache", "path": "/hom*" }"#,
            r#"{ "type": "session-cache" }"#,
            r#"{ "type": "session-cache", "path": "/../etc" }"#,
            r#"{ "type": "session-cache", "path": "/home/../etc" }"#,
            r#"{ "type": "project-cache", "path": "/../etc" }"#,
            r#"{ "type": "session-cache", "path": "/x?[y]" }"#,
            r#"{ "type": "project-cache", "path": "/x", "glob": "/x" }"#,
        ] {
            assert!(
                serde_json::from_str::<crate::spec::Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {mapping} ] }} }}"#
                ))
                .is_err(),
                "should reject {mapping}"
            );
        }
    }

    #[test]
    fn redirect_mappings_parse_and_contribute_a_redirect_permission() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "redirect-ro", "dest": "/bla", "source": "/otherdir" },
                { "type": "redirect-rw", "dest": "/data", "source": "/home/me/data" }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns::new(vec![
                (
                    "/bla".to_string(),
                    Permission::Redirect {
                        source: PathBuf::from("/otherdir"),
                        writable: false
                    }
                ),
                (
                    "/data".to_string(),
                    Permission::Redirect {
                        source: PathBuf::from("/home/me/data"),
                        writable: true
                    }
                ),
            ])
        );
        // Redirects are pure FUSE: they produce no sandbox ops.
        assert!(spec.hostfs.ops().is_empty());
        assert_eq!(
            spec.hostfs.mappings[0].describe(),
            "redirect-ro /otherdir -> /bla"
        );
        assert_eq!(
            spec.hostfs.mappings[1].describe(),
            "redirect-rw /home/me/data -> /data"
        );
    }

    #[test]
    fn redirect_mappings_reject_bad_destinations() {
        for mapping in [
            // dest must be absolute and wildcard-free...
            r#"{ "type": "redirect-ro", "dest": "bla", "source": "/otherdir" }"#,
            r#"{ "type": "redirect-ro", "dest": "/bl*", "source": "/otherdir" }"#,
            r#"{ "type": "redirect-ro", "dest": "/bl?", "source": "/otherdir" }"#,
            r#"{ "type": "redirect-ro", "dest": "/bl[a]", "source": "/otherdir" }"#,
            r#"{ "type": "redirect-ro", "dest": "/../etc", "source": "/otherdir" }"#,
            // ...and both fields must be present and non-empty.
            r#"{ "type": "redirect-ro", "dest": "/bla" }"#,
            r#"{ "type": "redirect-ro", "source": "/otherdir" }"#,
            r#"{ "type": "redirect-rw", "dest": "/bla", "source": "" }"#,
        ] {
            assert!(
                serde_json::from_str::<crate::spec::Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {mapping} ] }} }}"#
                ))
                .is_err(),
                "should reject {mapping}"
            );
        }
        // A relative source is fine (it is resolved against the spec dir
        // at load time) — unlike a relative dest.
        assert!(
            parse(r#"{ "hostfs": { "mappings": [ { "type": "redirect-ro", "dest": "/bla", "source": "otherdir" } ] } }"#)
                .hostfs
                .mappings[0]
                .describe()
                .contains("otherdir")
        );
    }

    #[test]
    fn bind_mounts_are_read_only_by_default() {
        // A bind mount bypasses the FUSE mirror's write policy, so it is
        // read-only unless the spec explicitly asks for `rw: true`.
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "bind", "src": "/etc" },
                { "type": "bind", "src": "/data", "rw": true }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.ops(),
            vec![
                Op::Bind {
                    src: "/etc".to_string(),
                    dest: PathBuf::from("/etc"),
                    rw: false
                },
                Op::Bind {
                    src: "/data".to_string(),
                    dest: PathBuf::from("/data"),
                    rw: true
                },
            ]
        );
        assert_eq!(spec.hostfs.mappings[0].describe(), "bind-ro /etc");
        assert_eq!(spec.hostfs.mappings[1].describe(), "bind-rw /data");
        // A non-boolean `rw` is rejected.
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "bind", "src": "/etc", "rw": "yes" } ] } }"#
            )
            .is_err()
        );
    }

    #[test]
    fn empty_tmpfs_and_bind_require_a_src() {
        for mapping in [
            r#"{ "type": "empty" }"#,
            r#"{ "type": "tmpfs" }"#,
            r#"{ "type": "bind" }"#,
            r#"{ "type": "symlink" }"#,
            r#"{ "type": "symlink", "src": "usr/lib" }"#,
        ] {
            assert!(
                serde_json::from_str::<crate::spec::Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {mapping} ] }} }}"#
                ))
                .is_err(),
                "should reject {mapping}"
            );
        }
    }

    #[test]
    fn mount_point_mappings_reject_relative_paths_and_bad_fields() {
        for mapping in [
            r#"{ "type": "dev", "path": "dev" }"#,
            r#"{ "type": "tmpfs", "path": "/tmp", "perms": "abc" }"#,
            r#"{ "type": "proc", "path": "/proc", "glob": "/proc" }"#,
            r#"{ "type": "bind", "src": "/usr", "dest": "usr" }"#,
            r#"{ "type": "bind", "src": "usr" }"#,
            r#"{ "type": "symlink", "src": "usr/lib", "dest": "lib" }"#,
        ] {
            assert!(
                serde_json::from_str::<crate::spec::Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {mapping} ] }} }}"#
                ))
                .is_err(),
                "should reject {mapping}"
            );
        }
    }

    #[test]
    fn mapping_ops_are_applied_in_mapping_order() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                 { "type": "dev", "path": "/dev" },
                 { "type": "symlink", "src": "usr/bin", "dest": "/bin" }
             ] } }"#,
        );
        assert_eq!(
            SandboxConfig::compile(&spec).ops,
            vec![
                // the dev mapping's op, first
                Op::Dev {
                    dest: PathBuf::from("/dev")
                },
                // the symlink mapping's op, second
                Op::Symlink {
                    src: "usr/bin".to_string(),
                    dest: PathBuf::from("/bin")
                },
            ]
        );
    }

    #[test]
    fn bind_mapping_accepts_the_deprecated_path_alias() {
        // Old spec files use `{"type": "bind", "path": "/etc"}`: accepted
        // as an alias for `src`, binding at the same path.
        let spec = parse(r#"{ "hostfs": { "mappings": [ { "type": "bind", "path": "/etc" } ] } }"#);
        assert_eq!(
            spec.hostfs.ops(),
            vec![Op::Bind {
                src: "/etc".to_string(),
                dest: PathBuf::from("/etc"),
                rw: false
            }]
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns::new(vec![("/etc".to_string(), Permission::Empty)])
        );
        // A relative `path` is rejected just like a relative `src`.
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "bind", "path": "etc" } ] } }"#
            )
            .is_err()
        );
    }

    #[test]
    fn proc_mapping_mounts_procfs() {
        let spec =
            parse(r#"{ "hostfs": { "mappings": [ { "type": "proc", "path": "/proc" } ] } }"#);
        assert_eq!(
            SandboxConfig::compile(&spec).ops,
            vec![Op::Proc {
                dest: PathBuf::from("/proc")
            }]
        );
        // And without any mount-point mapping, no procfs (and nothing
        // else) is mounted.
        let spec = parse(r#"{ "hostfs": { "mappings": [ { "type": "ro", "glob": "/etc" } ] } }"#);
        assert_eq!(SandboxConfig::compile(&spec).ops, vec![]);
    }
}
