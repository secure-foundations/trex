//! A lifter from Ghidra's variable export

use std::rc::Rc;

use crate::il::{AddressSpace, ExternalVariable, ILVariableMap, Program, Variable};
use crate::log::*;

fn parse_varnode(s: &str, extvar: &ExternalVariable, prog: &Rc<Program>) -> Option<Variable> {
    let mut components = s
        .trim()
        .strip_prefix('(')
        .unwrap()
        .strip_suffix(')')
        .unwrap()
        .split(',')
        .map(|x| x.trim());
    let addrspace = components.next().unwrap();
    let offset =
        usize::from_str_radix(components.next().unwrap().strip_prefix("0x").unwrap(), 16).unwrap();
    let size = components.next().unwrap().parse::<usize>().unwrap();
    assert_eq!(components.next(), None);

    if let Some((address_space_idx, _)) = prog
        .address_spaces
        .iter()
        .enumerate()
        .find(|(_, AddressSpace { name, .. })| name == addrspace)
    {
        Some(Variable::Varnode {
            address_space_idx,
            offset,
            size,
        })
    } else if addrspace == "stack" {
        Some(Variable::StackVariable {
            stack_offset: offset as u64 as i64,
            var_size: size,
        })
    } else {
        debug!(
            "Could not find the address space. Ignoring variable.";
            "var" => ?(addrspace, offset, size),
            "extvar" => %extvar.0,
        );
        None
    }
}

pub fn lift_from(vars_exported: &str, prog: &Rc<Program>) -> ILVariableMap {
    // Sanity check that we have a lift-able variables file
    assert!(vars_exported.starts_with("PROGRAM\n"));
    assert!(vars_exported.contains("VARIABLES\n"));

    // Grab the program section
    let program_section: Vec<&str> = vars_exported
        .trim()
        .lines()
        .skip_while(|&l| l != "PROGRAM")
        .skip(1)
        .take_while(|&l| !l.is_empty())
        .collect();

    // Get the stack pointer
    let stack_pointer = {
        assert!(program_section[0].starts_with("name"));
        assert!(program_section[1].starts_with("stack_pointer"));
        let sp_line: Vec<_> = program_section[1].split('\t').collect();
        assert_eq!(sp_line.len(), 3);
        let sp = sp_line[1].to_owned();
        let var = parse_varnode(sp_line[2], &ExternalVariable(sp.clone()), prog).unwrap();
        (sp, var)
    };

    // Grab the variables section
    let vars: Vec<&str> = vars_exported
        .trim()
        .lines()
        .skip_while(|&l| l != "VARIABLES")
        .skip(1)
        .take_while(|&l| !l.is_empty())
        .collect();

    // Parse out each variable
    let mut res = ILVariableMap {
        varmap: Default::default(),
        stack_pointer,
    };
    let mut lines = vars.iter().peekable();
    while let Some(line) = lines.next() {
        if line.trim() == "" {
            continue;
        }
        assert!(line.starts_with('\t') && !line.starts_with("\t\t"));
        let external_var = ExternalVariable(line.trim().to_owned());
        let func_name = line.split_once('@').unwrap().1.trim();
        let (func_name, func_address) = func_name.split_once('@').unwrap();
        let func_address = u64::from_str_radix(func_address, 16).unwrap();
        let func_id = prog
            .functions
            .iter()
            .enumerate()
            .find(|(_, (fn_name, _, _, entry_point))| {
                if fn_name == func_name {
                    if entry_point.0 != func_address {
                        debug!(
                            "Differing addresses for same function name found";
                            "fn_name" => fn_name,
                            "entry_point" => entry_point.0,
                            "func_address" => func_address,
                        );
                    }
                    true
                } else if entry_point.0 == func_address {
                    debug!(
                        "Different function name for same address found";
                        "external_var" => ?external_var,
                        "real_fn_name" => fn_name,
                        "variable_claimed_func_name" => func_name,
                    );
                    true
                } else {
                    false
                }
            })
            .ok_or_else(|| {
                debug!(
                    "Could not find function for variable";
                    "external_var" => ?external_var,
                    "func_name" => ?func_name,
                );
                format!("Could not find func_name: {func_name:?}")
            })
            .ok()
            .map(|x| x.0);

        let mut internal_vars = vec![];
        while let Some(line) = lines.peek() {
            if !line.starts_with("\t\t") {
                break;
            }

            if let Some(v) = parse_varnode(lines.next().unwrap(), &external_var, prog) {
                internal_vars.push(v);
            }
        }

        let prev = if let Some(func_id) = func_id {
            res.varmap
                .insert(external_var.clone(), (func_id, internal_vars))
        } else {
            None
        };
        if let Some(prev) = prev {
            warn!(
                "Ghidra variable parser found repeating variable name. Using latest.";
                "prev" => ?prev,
                "latest" => ?res.varmap.get(&external_var).unwrap(),
                "external_var" => ?external_var,
            );
        }
    }

    if res.varmap.is_empty() {
        debug!("No variables were parsed. Weird.");
    }

    res
}
