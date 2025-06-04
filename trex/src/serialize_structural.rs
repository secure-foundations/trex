//! Serlialize structural types to a machine-readable form

use std::collections::{BTreeMap, BTreeSet};

use crate::joinable_container::{Container, Index, IndexMap, IndexSet, Joinable};
use crate::structural::{BooleanOp, FloatOp, IntegerOp, StructuralType};

/// A trait that indicates that `Self` can be parsed from a string.
pub trait Parseable: Sized {
    /// Parse from the given string, returning `None` if unsuccessful
    fn parse_from(s: &str) -> Option<Self>;
}

/// A serializable form of structural types
#[derive(Debug)]
pub struct SerializableStructuralTypes<Var: std::fmt::Display> {
    map: BTreeMap<Var, Index>,
    type_names: IndexMap<String>,
    types: Container<StructuralType>,
}

impl<Var: std::fmt::Display> SerializableStructuralTypes<Var> {
    /// A new serializable structural types container.
    ///
    /// `type_names` can be used to provide better names to types; use `Default::default` if
    /// automatic name-picking is preferred. If not using default, then care must be taken regarding
    /// canonical indexing.
    pub fn new(
        varmap: BTreeMap<Var, Index>,
        type_names: IndexMap<String>,
        mut types: Container<StructuralType>,
    ) -> Self {
        types.garbage_collect_with_roots(varmap.values().cloned());
        assert!(type_names
            .iter()
            .all(|(_, name)| !name.starts_with("__t") && !name.contains(&[' ', '\n', '\t'][..])));
        Self {
            map: varmap,
            type_names,
            types,
        }
    }

    /// Get the (internal) container of types
    pub fn types(&self) -> &Container<StructuralType> {
        &self.types
    }

    /// Mutably get the (internal) container of types
    pub fn types_mut(&mut self) -> &mut Container<StructuralType> {
        &mut self.types
    }

    /// Serialize the structural types
    pub fn serialize(&self) -> String {
        let mut res = String::new();
        self.serialize_to(&mut res).unwrap();
        res
    }

    /// Try getting the canonical name for the type at `idx`. You almost definitely want
    /// [`Self::type_name`] instead.
    pub fn try_type_name(&self, idx: Index) -> Option<String> {
        let idx = self.types.get_canonical_index(idx);
        self.type_names.get(idx).cloned()
    }

    /// Get a canonical name for the type at `idx`
    pub fn type_name(&self, idx: Index) -> String {
        let idx = self.types.get_canonical_index(idx);

        if self.type_names.is_empty() {
            format!("t{}", self.types.get_canonical_index(idx).to_string())
        } else {
            self.try_type_name(idx).unwrap_or_else(|| {
                format!("__t{}", self.types.get_canonical_index(idx).to_string())
            })
        }
    }

    /// Get the type at `idx`
    pub fn type_at(&self, idx: Index) -> &StructuralType {
        &self.types[idx]
    }

    /// Get an iterator to the variables and their types
    pub fn var_type_iter(&self) -> impl Iterator<Item = (&Var, Index)> {
        self.map.iter().map(|(k, v)| (k, *v))
    }

    /// Serialize to the given string
    fn serialize_to(&self, f: &mut String) -> std::fmt::Result {
        use std::fmt::Write;

        writeln!(f, "VAR_MAP")?;
        for (var, idx) in self.map.iter() {
            writeln!(f, "\t{}\t{}", var, self.type_name(*idx))?;
        }
        writeln!(f)?;

        writeln!(f, "STRUCTURAL_TYPES")?;

        let mut seen = IndexSet::new();
        let mut queue: Vec<Index> = self.map.values().cloned().collect();

        while let Some(idx) = queue.pop() {
            let idx = self.types.get_canonical_index(idx);
            if !seen.insert(idx) {
                continue;
            }
            let typ = &self.types[idx];
            queue.extend(typ.refers_to());

            writeln!(f, "\t{}", self.type_name(idx))?;

            let StructuralType {
                upper_bound_size,
                copy_sizes,
                zero_comparable,
                pointer_to,
                observed_boolean,
                integer_ops,
                boolean_ops,
                float_ops,
                observed_code,
                colocated_struct_fields,
                observed_array,
                is_type_for_il_constant_variable,
            } = typ;

            macro_rules! w {
                (_ $n:ident $v:expr) => {
                    writeln!(f, "\t\t{}\t{}", stringify!($n).to_uppercase(), $v)?;
                };
                (b $e:ident) => {
                    if *$e {
                        writeln!(f, "\t\t{}", stringify!($e).to_uppercase())?;
                    }
                };
                (opsset $e:ident) => {
                    if !$e.is_empty() {
                        writeln!(
                            f,
                            "\t\t{}\t{{{}}}",
                            stringify!($e).to_uppercase(),
                            $e.into_iter()
                                .collect::<BTreeSet<_>>()
                                .into_iter()
                                .map(|(op, sz)| format!("{:?}_{}", op, sz))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )?;
                    }
                };
                (s $e:ident) => {
                    if !$e.is_empty() {
                        writeln!(
                            f,
                            "\t\t{}\t{:?}",
                            stringify!($e).to_uppercase(),
                            $e.into_iter().collect::<BTreeSet<_>>()
                        )?;
                    }
                };
                (o $e:ident $f:expr) => {
                    if let Some(v) = $e {
                        writeln!(f, "\t\t{}\t{}", stringify!($e).to_uppercase(), $f(v))?;
                    }
                };
            }

            w!(o upper_bound_size |&t| t);
            w!(s copy_sizes);
            w!(b zero_comparable);
            w!(o pointer_to |&t| self.type_name(t));
            w!(b observed_boolean);
            w!(opsset integer_ops);
            w!(opsset boolean_ops);
            w!(opsset float_ops);
            w!(b observed_code);
            for (offset, coloidx) in colocated_struct_fields {
                w!(_ colocated_struct_fields format_args!("{}\t{}", offset, self.type_name(*coloidx)));
            }
            w!(b observed_array);
            w!(b is_type_for_il_constant_variable);
            writeln!(f)?;
        }

        Ok(())
    }
}

impl<Var> SerializableStructuralTypes<Var>
where
    Var: std::fmt::Display + Parseable + std::cmp::Ord,
{
    /// Get the index of the type for `var`
    pub fn index_of_type_for(&self, var: &Var) -> Option<Index> {
        self.map.get(var).cloned()
    }
}

impl<Var> Parseable for SerializableStructuralTypes<Var>
where
    Var: std::fmt::Display + Parseable + std::cmp::Ord,
{
    fn parse_from(s: &str) -> Option<Self> {
        let mut s = s.lines().filter(|l| !l.contains("[WARN]")).peekable();

        assert_eq!(s.next().unwrap(), "VAR_MAP");

        let mut ret = Self {
            map: Default::default(),
            type_names: Default::default(),
            types: Container::new(),
        };

        let mut type_name_map: BTreeMap<&str, Index> = Default::default();

        macro_rules! ty {
            ($name:expr) => {
                *type_name_map
                    .entry($name.trim())
                    .or_insert_with(|| ret.types.insert_default())
            };
        }

        while s.peek().unwrap().starts_with('\t') {
            let mut line = s.next().unwrap().trim().split('\t');

            let var = Var::parse_from(line.next().unwrap())?;
            let typ = line.next().unwrap();

            let prev = ret.map.insert(var, ty!(typ));
            assert!(prev.is_none());
        }

        assert_eq!(s.next().unwrap(), "");
        assert_eq!(s.next().unwrap(), "STRUCTURAL_TYPES");

        while let Some(line) = s.next() {
            if line.trim() == "" {
                continue;
            }
            assert!(line.starts_with('\t'));
            let line = line.trim();
            let tyi = ty!(line);
            let mut typ = Default::default();

            while s.peek().unwrap().starts_with("\t\t") {
                let line = s.next().unwrap().trim();
                let (desc, body) = line.split_once('\t').unwrap_or((line, ""));

                let StructuralType {
                    upper_bound_size,
                    copy_sizes,
                    zero_comparable,
                    pointer_to,
                    observed_boolean,
                    integer_ops,
                    boolean_ops,
                    float_ops,
                    observed_code,
                    colocated_struct_fields,
                    observed_array,
                    is_type_for_il_constant_variable,
                } = &mut typ;

                match desc {
                    "UPPER_BOUND_SIZE" => *upper_bound_size = Some(body.trim().parse().unwrap()),
                    "COPY_SIZES" => {
                        *copy_sizes = body
                            .trim()
                            .trim_matches(&['{', '}'][..])
                            .split(',')
                            .map(|x| x.trim().parse().unwrap())
                            .collect()
                    }
                    "ZERO_COMPARABLE" => *zero_comparable = true,
                    "POINTER_TO" => *pointer_to = Some(ty!(body)),
                    "OBSERVED_BOOLEAN" => *observed_boolean = true,
                    "INTEGER_OPS" => {
                        *integer_ops = body
                            .trim()
                            .trim_matches(&['{', '}'][..])
                            .split(',')
                            .map(|x| {
                                let (x, sz) = x.trim().split_once('_').unwrap();
                                (
                                    IntegerOp::all_ops()
                                        .into_iter()
                                        .find(|op| format!("{:?}", op) == x)
                                        .unwrap(),
                                    sz.parse().unwrap(),
                                )
                            })
                            .collect()
                    }
                    "BOOLEAN_OPS" => {
                        *boolean_ops = body
                            .trim()
                            .trim_matches(&['{', '}'][..])
                            .split(',')
                            .map(|x| {
                                let (x, sz) = x.trim().split_once('_').unwrap();
                                (
                                    BooleanOp::all_ops()
                                        .into_iter()
                                        .find(|op| format!("{:?}", op) == x)
                                        .unwrap(),
                                    sz.parse().unwrap(),
                                )
                            })
                            .collect()
                    }
                    "FLOAT_OPS" => {
                        *float_ops = body
                            .trim()
                            .trim_matches(&['{', '}'][..])
                            .split(',')
                            .map(|x| {
                                let (x, sz) = x.trim().split_once('_').unwrap();
                                (
                                    FloatOp::all_ops()
                                        .into_iter()
                                        .find(|op| format!("{:?}", op) == x)
                                        .unwrap(),
                                    sz.parse().unwrap(),
                                )
                            })
                            .collect()
                    }
                    "OBSERVED_CODE" => *observed_code = true,
                    "COLOCATED_STRUCT_FIELDS" => {
                        let (offset, coloidx) = body.split_once('\t').unwrap();
                        let offset = offset.trim().parse::<usize>().unwrap().try_into().unwrap();
                        let coloidx = ty!(coloidx);
                        let prev = colocated_struct_fields.insert(offset, coloidx);
                        assert!(prev.is_none());
                    }
                    "OBSERVED_ARRAY" => *observed_array = true,
                    "IS_TYPE_FOR_IL_CONSTANT_VARIABLE" => *is_type_for_il_constant_variable = true,
                    _ => unreachable!(),
                }
            }

            ret.types[tyi] = typ;

            assert_eq!(s.next().unwrap(), "");
        }

        ret.type_names = type_name_map
            .into_iter()
            .map(|(nm, idx)| (idx, nm.into()))
            .collect();

        Some(ret)
    }
}
