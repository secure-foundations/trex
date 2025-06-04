//! A lifter from Ghidra's P-Code
//!
//! See `ghidra_pcode_exporter/README.md` for how to use the `ghidra_pcode_exporter` script to
//! produce the required `.pcode-exported` file that this lifter can import.

use crate::containers::unordered::UnorderedMap;
use crate::il::{AddressSpace, Endian, Instruction, Op, Program, Variable};
use crate::inference_config::CONFIG;
use crate::log::*;

use std::convert::TryInto;
use std::rc::Rc;

use itertools::Itertools;

/// Lift `.pcode-exported` to a program on which type inference can be performed.
pub fn lift_from(pcode_exported: &str) -> Rc<Program> {
    // Sanity check that we have a lift-able `.pcode-exported` file
    assert!(pcode_exported.starts_with("PROGRAM\n"));
    assert!(pcode_exported.contains("ADDRESS_SPACES\n"));
    assert!(pcode_exported.contains("PCODE_LISTING\n"));

    // Grab the sections
    let mut sections = pcode_exported.trim().split("\n\n");
    let program_section: &str = sections
        .next()
        .unwrap()
        .strip_prefix("PROGRAM\n")
        .unwrap()
        .trim();
    let addr_spaces_section: &str = sections
        .next()
        .unwrap()
        .strip_prefix("ADDRESS_SPACES\n")
        .unwrap()
        .trim();
    let pcode_listing_section = {
        let mut s: Vec<&str> = sections.map(|x| x.trim()).collect();
        assert!(!s.is_empty());
        s[0] = s[0].strip_prefix("PCODE_LISTING").unwrap().trim();
        if s[0] == "" {
            s.into_iter().skip(1).collect()
        } else {
            s
        }
    };

    // Parse the program section
    let (program_name, endianness) = {
        let mut s = program_section.split('\n');
        let name: &str = match &*s.next().unwrap().trim().split(' ').collect::<Vec<_>>() {
            ["name", n] => n,
            l => panic!("Expected `name`, got {:?}", l),
        };
        let endianness = match &*s.next().unwrap().trim().split(' ').collect::<Vec<_>>() {
            ["big_endian", "false"] => Endian::Little,
            ["big_endian", "true"] => Endian::Big,
            l => panic!("Expected `big_endian`, got {:?}", l),
        };
        (name, endianness)
    };
    let _ = program_name; // XXX: Do we want to hold on to program name for some reason?

    // Parse the address spaces section
    let ram_wordsize = addr_spaces_section
        .split('\n')
        .filter_map(|l| {
            let l = l.trim().split(' ').collect::<Vec<_>>();
            assert_eq!(l.len(), 3);
            (l[1] == "ram").then(|| l[2].parse().unwrap())
        })
        .next()
        .unwrap();
    let address_space_map = addr_spaces_section
        .split('\n')
        .map(|l| {
            let l = l.trim().split(' ').collect::<Vec<_>>();
            assert_eq!(l.len(), 3);
            (
                Ok(l[0].parse::<usize>().unwrap()),
                AddressSpace {
                    name: l[1].to_owned(),
                    endianness,
                    wordsize: l[2].parse().unwrap(),
                },
            )
        })
        // XXX: Why does Ghidra not tell us about the `unique` space?
        .chain(std::iter::once((
            Err("unique"),
            AddressSpace {
                name: "unique".to_owned(),
                endianness,
                wordsize: ram_wordsize,
            },
        )))
        // XXX: Why does Ghidra not tell us about the `register` space?
        .chain(std::iter::once((
            Err("register"),
            AddressSpace {
                name: "register".to_owned(),
                endianness,
                wordsize: ram_wordsize,
            },
        )))
        .enumerate()
        .map(|(i, (a, b))| (a, (i, b)));
    let address_spaces: Vec<AddressSpace> =
        address_space_map.clone().map(|(_, (_, a))| a).collect();
    let address_space_map: UnorderedMap<Result<usize, &'static str>, (usize, AddressSpace)> =
        address_space_map.collect();
    assert_eq!(address_spaces.len(), address_space_map.len());

    // Parse the pcode listing section
    let mut aux_data_when_parsing_pcode_listing = AuxDataWhenParsingPCodeListing::new();
    let fns = pcode_listing_section.iter().map(|func| {
        let (fn_name, rest) = func.split_once('\n').unwrap();
        (
            u64::from_str_radix(fn_name.trim().split_once(' ').unwrap().0, 16).unwrap(),
            fn_name.trim().split_once(' ').unwrap().1,
            match rest.split_once('\n') {
                Some((unaffected_line, func_listing)) => (
                    parse_unaffected_line(unaffected_line, &address_space_map),
                    parse_pcode_listing(
                        &mut aux_data_when_parsing_pcode_listing,
                        func_listing,
                        &address_space_map,
                    ),
                ),
                None => (parse_unaffected_line(rest, &address_space_map), vec![]),
            },
        )
    });

    // Make the program
    let mut prog = Program::new(address_spaces);
    for (entry_point, fn_name, (unaffected, fn_ins_list)) in fns {
        prog.begin_function(fn_name.to_string(), unaffected, entry_point);
        for il_inss in fn_ins_list {
            prog.add_one_machine_instruction(il_inss);
        }
        prog.end_function();
    }
    for (sp, mc_target) in aux_data_when_parsing_pcode_listing.sp_fixups {
        trace!("SP unaffected fixup"; "sp" => ?sp, "target" => mc_target);
        prog.add_aux_data_for_stack_pointer_fixups(sp, mc_target);
    }
    for (mc_addr, comm) in aux_data_when_parsing_pcode_listing.machine_addr_comments {
        prog.add_comment_to_machine_address(mc_addr, &comm);
    }
    Rc::new(prog)
}

fn parse_unaffected_line(
    line: &str,
    address_space_map: &UnorderedMap<Result<usize, &'static str>, (usize, AddressSpace)>,
) -> Vec<Variable> {
    let (ident, body) = line.trim().split_once(':').unwrap();
    assert_eq!(ident.trim(), "Unaffected");
    let mut body = body.trim();
    let mut res = vec![];
    while !body.is_empty() {
        let (v, _, rest) = parse_variable(body, address_space_map);
        res.push(v);
        body = rest;
    }
    res
}

struct AuxDataWhenParsingPCodeListing {
    sp_fixups: Vec<(Variable, u64)>,
    machine_addr_comments: UnorderedMap<u64, String>,
}
impl AuxDataWhenParsingPCodeListing {
    fn new() -> Self {
        Self {
            sp_fixups: Default::default(),
            machine_addr_comments: Default::default(),
        }
    }
}

fn parse_pcode_listing(
    aux_data: &mut AuxDataWhenParsingPCodeListing,
    func_listing: &str,
    address_space_map: &UnorderedMap<Result<usize, &'static str>, (usize, AddressSpace)>,
) -> Vec<Vec<Instruction>> {
    enum CallStateMachine {
        NotInCall,
        AfterCallComment,
        AfterSubtractSP(String),
        AfterStoreRet(String),
    }
    let mut call_state_machine = CallStateMachine::NotInCall;
    let mut latest_comment: String = "<begin>".into();

    func_listing
        // Get each line
        .split('\n')
        .map(|l| l.trim())
        // Ignore any comments, and change over to IL instructions
        .flat_map(|l| {
            // TODO: Consider doing this without relying on comments, instead by looking for a
            // direct branch-to-next-instruction itself.
            if l.trim().starts_with(";; ") {
                latest_comment = l.split_once(";; ").unwrap().1.into();
                if l.contains(";; CALL ") {
                    call_state_machine = CallStateMachine::AfterCallComment;
                } else {
                    call_state_machine = CallStateMachine::NotInCall;
                }
                vec![]
            } else {
                let address = u64::from_str_radix(l.split(' ').next().unwrap(), 16).unwrap();
                aux_data.machine_addr_comments.insert(address, latest_comment.clone());

                match &call_state_machine {
                    CallStateMachine::NotInCall => {
                        vec![parse_pcode_line(l, address_space_map)]
                    }
                    CallStateMachine::AfterCallComment => {
                        if l.contains(" COPY ") || l.contains(" INT_ADD ") || l.contains(" LOAD ") || l.contains(" INT_MULT ") {
                            // something like `CALL RDX` or `CALL [ECX+0x60]` or `CALL
                            // [EAX*4+0x8049f14] or similar; treat this line like normal (without
                            // updating state machine) and continue to next
                            vec![parse_pcode_line(l, address_space_map)]
                        } else if l.contains(" INT_SUB ") {
                            if CONFIG.stack_pointer_patch_after_call_fallthrough {
                                let (left, right) = l.split_once(") INT_SUB (").unwrap();
                                let (_, left) = left.split_once('(').unwrap();
                                let (right, _) = right.split_once(')').unwrap();
                                assert_eq!(left, right, "Expected SP to be equal");
                            }
                            call_state_machine = CallStateMachine::AfterSubtractSP(l.to_string());
                            vec![parse_pcode_line(l, address_space_map)]
                        } else {
                            panic!("Unexpected instruction after CALL comment: {:?}", l);
                        }
                    }
                    CallStateMachine::AfterSubtractSP(subinsn) => {
                        if CONFIG.stack_pointer_patch_after_call_fallthrough {
                            assert!(
                                l.contains(" STORE "),
                                "Expected STORE instruction after CALL comment and INT_SUB: {l:?}"
                            );
                        }
                        call_state_machine = CallStateMachine::AfterStoreRet(subinsn.clone());
                        vec![parse_pcode_line(l, address_space_map)]
                    }
                    CallStateMachine::AfterStoreRet(subinsn) => {
                        let addinsn = subinsn.replace("INT_SUB", "INT_ADD");
                        call_state_machine = CallStateMachine::NotInCall;
                        let line1 = if l.contains("---  BRANCH ")
                            && CONFIG.fix_ghidra_branch_to_next_insn_as_call_with_fallthrough
                        {
                            trace!("Fixing Ghidra branch -> callwithfallthrough"; "line" => ?l);
                            let l = l.replace("---  BRANCH ", "---  CALLWITHFALLTHROUGH ");
                            parse_pcode_line(&l, address_space_map)
                        } else {
                            parse_pcode_line(&l, address_space_map)
                        };
                        if CONFIG.stack_pointer_patch_after_call_fallthrough {
                            trace!(
                                "Fixing Ghidra stackpointer after call";
                                "line" => ?l,
                                "addinsn" => ?addinsn,
                            );
                            let line2 = parse_pcode_line(&addinsn, address_space_map);
                            match line1.inputs[0] {
                                Variable::MachineAddress { addr } => {
                                    let stack_pointer = line2.output.clone();
                                    aux_data.sp_fixups.push((stack_pointer, addr));
                                },
                                _ => {
                                    trace!("Non-machine address, skipping SP fixup"; "line" => ?l, "line1" => ?line1);
                                }
                            }
                            vec![line1, line2]
                        } else {
                            vec![line1]
                        }
                    }
                }
            }
        })
        // Group so that we can use `Program::add_one_machine_instruction`
        .group_by(|i| i.address)
        .into_iter()
        .map(|(_key, group)| group.collect())
        .collect()
}

fn parse_pcode_line(
    line: &str,
    address_space_map: &UnorderedMap<Result<usize, &'static str>, (usize, AddressSpace)>,
) -> Instruction {
    let address = u64::from_str_radix(line.split(' ').next().unwrap(), 16).unwrap();
    let pcode = line.split(' ').skip(1).join(" ");

    let (output, op, inputs, indirect_targets, s) = parse_op(&pcode, address_space_map);
    assert!(s.trim().is_empty(), "Line unfinished {s:?}");

    Instruction {
        address,
        output,
        op,
        inputs,
        indirect_targets,
    }
}

fn varnode_to_pc(
    v: Variable,
    address_space_map: &UnorderedMap<Result<usize, &'static str>, (usize, AddressSpace)>,
    const_allowed: bool,
) -> Variable {
    match v {
        Variable::Varnode {
            address_space_idx,
            offset,
            size: _,
        } => {
            let a: Vec<_> = address_space_map
                .values()
                .filter_map(|(i, a)| (*i == address_space_idx).then(|| a))
                .collect();
            assert_eq!(a.len(), 1);
            assert_eq!(a[0].name, "ram");
            Variable::MachineAddress {
                addr: offset.try_into().unwrap(),
            }
        }
        Variable::Constant { value, size: _ } if const_allowed => Variable::ILOffset {
            offset: u32::try_from(value).unwrap() as i32 as isize,
        },
        _ => unreachable!(),
    }
}

fn parse_variable<'a>(
    inp: &'a str,
    address_space_map: &UnorderedMap<Result<usize, &'static str>, (usize, AddressSpace)>,
) -> (Variable, u64, &'a str) {
    let inp = inp.trim_start();
    if let Some(rest) = inp.strip_prefix("---") {
        return (Variable::Unused, 0, rest.trim_start());
    }
    let (addr_space, offset, size, rest_start) = {
        let mut s = inp.split([' ', '\t']);
        let a = s
            .next()
            .unwrap()
            .strip_prefix('(')
            .unwrap()
            .strip_suffix(',')
            .unwrap();
        let b = u64::from_str_radix(
            s.next()
                .unwrap()
                .strip_suffix(',')
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16,
        )
        .unwrap();
        let c: u64 = s
            .next()
            .unwrap()
            .strip_suffix(')')
            .unwrap()
            .parse()
            .unwrap();
        (a, b, c, inp.split([' ', '\t']).take(3).join(" ").len())
    };

    let var = match addr_space {
        "const" => Variable::Constant {
            value: offset,
            size: size.try_into().unwrap(),
        },
        var => {
            let addrspcs: Vec<&(usize, AddressSpace)> = address_space_map
                .iter()
                .map(|(_, a)| a)
                .filter(|(_i, a)| a.name == var)
                .collect();
            assert_eq!(addrspcs.len(), 1, "Could not find address space `{}`", var);
            let (address_space_idx, _addrspc) = addrspcs[0];
            Variable::Varnode {
                address_space_idx: *address_space_idx,
                offset: offset.try_into().unwrap(),
                size: size.try_into().unwrap(),
            }
        }
    };

    (
        var,
        size,
        inp[rest_start..].trim_start_matches(&[' ', ','][..]),
    )
}

fn get_const(v: Variable) -> u64 {
    match v {
        Variable::Constant { value, size: _ } => value,
        _ => unreachable!(),
    }
}

fn parse_op<'a>(
    inp: &'a str,
    address_space_map: &UnorderedMap<Result<usize, &'static str>, (usize, AddressSpace)>,
) -> (Variable, Op, [Variable; 2], Vec<Variable>, &'a str) {
    let inp = inp.trim_start();

    let (output, _, rest) = parse_variable(inp, address_space_map);
    let (op, rest) = rest.split_once(' ').unwrap();
    match op {
        "STORE" => {
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            let (v1, _, rest) = parse_variable(rest, address_space_map);
            let (v2, v2_size, rest) = parse_variable(rest, address_space_map);
            let (derefval_address_space_idx, address_space) = match v0 {
                Variable::Constant { value, size: _ } => {
                    // The constant tells us Ghidra's space index, so we look up our own internal
                    // index from the map
                    address_space_map
                        .get(&Ok(value.try_into().unwrap()))
                        .unwrap()
                }
                _ => unreachable!(),
            };
            let (addr_address_space_idx, addr_offset, derefval_size) = match v1 {
                Variable::Varnode {
                    address_space_idx,
                    offset,
                    size,
                } => {
                    assert_eq!(size, address_space.wordsize);
                    (address_space_idx, offset, v2_size.try_into().unwrap())
                }
                _ => unreachable!(),
            };
            let dst = Variable::DerefVarnode {
                derefval_address_space_idx: *derefval_address_space_idx,
                derefval_size,
                addr_address_space_idx,
                addr_offset,
            };
            (output, Op::Store, [dst, v2], vec![], rest)
        }
        "LOAD" => {
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            let (v1, _, rest) = parse_variable(rest, address_space_map);
            let (derefval_address_space_idx, address_space) = match v0 {
                Variable::Constant { value, size: _ } => {
                    // The constant tells us Ghidra's space index, so we look up our own internal
                    // index from the map
                    address_space_map
                        .get(&Ok(value.try_into().unwrap()))
                        .unwrap()
                }
                _ => unreachable!(),
            };
            let (addr_address_space_idx, addr_offset, derefval_size) = match v1 {
                Variable::Varnode {
                    address_space_idx,
                    offset,
                    size,
                } => {
                    assert_eq!(size, address_space.wordsize);
                    (address_space_idx, offset, output.try_size().unwrap())
                }
                _ => unreachable!(),
            };
            let src = Variable::DerefVarnode {
                derefval_address_space_idx: *derefval_address_space_idx,
                derefval_size,
                addr_address_space_idx,
                addr_offset,
            };
            (output, Op::Load, [src, Variable::Unused], vec![], rest)
        }
        "CALLWITHFALLTHROUGH" | "CALLWITHNOFALLTHROUGH" => {
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            let target = varnode_to_pc(v0, address_space_map, false);
            let op = match op {
                "CALLWITHFALLTHROUGH" => Op::CallWithFallthrough,
                "CALLWITHNOFALLTHROUGH" => Op::CallWithNoFallthrough,
                _ => unreachable!(),
            };
            (output, op, [target, Variable::Unused], vec![], rest)
        }
        "COPY" | "BOOL_NEGATE" | "POPCOUNT" | "INT_2COMP" | "INT_NEGATE" | "INT_ZEXT"
        | "INT_SEXT" | "RETURN" => {
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            let op = match op {
                "COPY" => Op::Copy,
                "BOOL_NEGATE" => Op::BoolNegate,
                "POPCOUNT" => Op::Popcount,
                "INT_2COMP" => Op::IntTwosComp,
                "INT_NEGATE" => Op::IntOnesComp,
                "INT_ZEXT" => Op::IntZext,
                "INT_SEXT" => Op::IntSext,
                "RETURN" => Op::Return,
                _ => unreachable!("{}", op),
            };
            (output, op, [v0, Variable::Unused], vec![], rest)
        }
        "BRANCHIND" | "CALLWITHFALLTHROUGHIND" | "CALLWITHNOFALLTHROUGHIND" => {
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            let op = match op {
                "BRANCHIND" => Op::BranchIndOffset,
                "CALLWITHFALLTHROUGHIND" => Op::CallWithFallthroughIndirect,
                "CALLWITHNOFALLTHROUGHIND" => Op::CallWithNoFallthroughIndirect,
                _ => unreachable!("{}", op),
            };
            let rest = rest
                .trim()
                .strip_prefix("INDIRECT_TARGETS:")
                .unwrap()
                .trim();
            let indirect_targets = rest
                .split(' ')
                .filter_map(|v| {
                    if v.trim() == "" {
                        None
                    } else {
                        Some(Variable::MachineAddress {
                            addr: u64::from_str_radix(v.trim(), 16).unwrap(),
                        })
                    }
                })
                .collect();
            (output, op, [v0, Variable::Unused], indirect_targets, "")
        }
        "INT_ADD" | "INT_EQUAL" | "INT_NOTEQUAL" | "INT_SUB" | "INT_CARRY" | "INT_SCARRY"
        | "INT_SBORROW" | "INT_SLESS" | "INT_LESS" | "INT_AND" | "INT_OR" | "INT_XOR"
        | "INT_MULT" | "INT_DIV" | "INT_REM" | "INT_SDIV" | "INT_SREM" | "INT_LEFT"
        | "INT_RIGHT" | "INT_SRIGHT" | "BOOL_OR" | "BOOL_AND" | "BOOL_XOR" | "PIECE"
        | "SUBPIECE" => {
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            let (v1, _, rest) = parse_variable(rest, address_space_map);
            let op = match op {
                "INT_ADD" => Op::IntAdd,
                "INT_EQUAL" => Op::IntEqual,
                "INT_NOTEQUAL" => Op::IntNotEqual,
                "INT_SUB" => Op::IntSub,
                "INT_CARRY" => Op::IntCarry,
                "INT_SCARRY" => Op::IntSCarry,
                "INT_SBORROW" => Op::IntSBorrow,
                "INT_LESS" => Op::IntLess,
                "INT_SLESS" => Op::IntSLess,
                "INT_AND" => Op::IntAnd,
                "INT_OR" => Op::IntOr,
                "INT_XOR" => Op::IntXor,
                "INT_MULT" => Op::IntMult,
                "INT_DIV" => Op::IntUDiv,
                "INT_REM" => Op::IntURem,
                "INT_SDIV" => Op::IntSDiv,
                "INT_SREM" => Op::IntSRem,
                "INT_LEFT" => Op::IntLeftShift,
                "INT_RIGHT" => Op::IntURightShift,
                "INT_SRIGHT" => Op::IntSRightShift,
                "BOOL_AND" => Op::BoolAnd,
                "BOOL_OR" => Op::BoolOr,
                "BOOL_XOR" => Op::BoolXor,
                "PIECE" => Op::Piece,
                "SUBPIECE" => Op::SubPiece,
                _ => unreachable!("{}", op),
            };
            (output, op, [v0, v1], vec![], rest)
        }
        "INT2FLOAT" | "TRUNC" | "ROUND" | "FLOAT2FLOAT" | "FLOAT_NEG" | "FLOAT_ABS"
        | "FLOAT_SQRT" => {
            let op = match op {
                "INT2FLOAT" => Op::Int2Float,
                "TRUNC" => Op::Float2IntTrunc,
                "ROUND" => Op::FloatRound,
                "FLOAT2FLOAT" => Op::Float2Float,
                "FLOAT_NEG" => Op::FloatNeg,
                "FLOAT_ABS" => Op::FloatAbs,
                "FLOAT_SQRT" => Op::FloatSqrt,
                _ => unreachable!("{}", op),
            };
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            (output, op, [v0, Variable::Unused], vec![], rest)
        }
        "FLOAT_NAN" => {
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            (output, Op::FloatIsNan, [v0, Variable::Unused], vec![], rest)
        }
        "FLOAT_ADD" | "FLOAT_SUB" | "FLOAT_MULT" | "FLOAT_DIV" | "FLOAT_EQUAL"
        | "FLOAT_NOTEQUAL" | "FLOAT_LESS" | "FLOAT_LESSEQUAL" => {
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            let (v1, _, rest) = parse_variable(rest, address_space_map);
            let op = match op {
                "FLOAT_ADD" => Op::FloatAdd,
                "FLOAT_SUB" => Op::FloatSub,
                "FLOAT_MULT" => Op::FloatMult,
                "FLOAT_DIV" => Op::FloatDiv,
                "FLOAT_EQUAL" => Op::FloatEqual,
                "FLOAT_NOTEQUAL" => Op::FloatNotEqual,
                "FLOAT_LESS" => Op::FloatLess,
                "FLOAT_LESSEQUAL" => Op::FloatLessEqual,
                _ => unreachable!("{}", op),
            };
            (output, op, [v0, v1], vec![], rest)
        }
        "BRANCH" => {
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            let target = varnode_to_pc(v0, address_space_map, true);
            (output, Op::Branch, [target, Variable::Unused], vec![], rest)
        }
        "CBRANCH" => {
            let (v0, _, rest) = parse_variable(rest, address_space_map);
            let (v1, _, rest) = parse_variable(rest, address_space_map);
            let target = varnode_to_pc(v0, address_space_map, true);
            (output, Op::Cbranch, [target, v1], vec![], rest)
        }
        "NOP" => {
            assert_eq!(rest.trim(), "---");
            (
                output,
                Op::Nop,
                [Variable::Unused, Variable::Unused],
                vec![],
                "",
            )
        }
        "CALLOTHER" => {
            let (c, _, rest) = parse_variable(rest, address_space_map);
            fn munch(rest: &str) -> &str {
                assert!(
                    rest.starts_with("\tCALLOTHER_OPCODE:"),
                    "Found non-CALLOTHER_OPCODE: {}",
                    rest
                );
                ""
            }
            let callother_opcode = rest.trim().rsplit_once(' ').unwrap_or_default().1;
            match callother_opcode {
                "invalidInstructionException" => {
                    // An x86 "ud2".
                    (
                        output,
                        Op::ProcessorException,
                        [Variable::Unused, Variable::Unused],
                        vec![],
                        munch(rest),
                    )
                }
                "cpuid"
                | "cpuid_Architectural_Performance_Monitoring_info"
                | "cpuid_Deterministic_Cache_Parameters_info"
                | "cpuid_Direct_Cache_Access_info"
                | "cpuid_Extended_Feature_Enumeration_info"
                | "cpuid_Extended_Topology_info"
                | "cpuid_MONITOR_MWAIT_Features_info"
                | "cpuid_Processor_Extended_States_info"
                | "cpuid_Quality_of_Service_info"
                | "cpuid_Thermal_Power_Management_info"
                | "cpuid_Version_info"
                | "cpuid_basic_info"
                | "cpuid_brand_part1_info"
                | "cpuid_brand_part2_info"
                | "cpuid_brand_part3_info"
                | "cpuid_cache_tlb_info"
                | "cpuid_serial_info" => {
                    // various CPUID related operations
                    let (v0, _, rest) = parse_variable(rest, address_space_map);
                    (
                        output,
                        Op::UnderspecifiedOutputModification,
                        [v0, Variable::Unused],
                        vec![],
                        munch(rest),
                    )
                }
                "vpxor_avx" => {
                    // vpxor
                    let (v0, _, rest) = parse_variable(rest, address_space_map);
                    let (v1, _, rest) = parse_variable(rest, address_space_map);
                    (output, Op::IntXor, [v0, v1], vec![], munch(rest))
                }
                "vpand_avx" | "vpand_avx2" => {
                    // vpand
                    let (v0, _, rest) = parse_variable(rest, address_space_map);
                    let (v1, _, rest) = parse_variable(rest, address_space_map);
                    (output, Op::IntAnd, [v0, v1], vec![], munch(rest))
                }
                "vpadd_avx2" | "vpaddq_avx2" | "vpaddq_avx" => {
                    // vpadd
                    let (v0, _, rest) = parse_variable(rest, address_space_map);
                    let (v1, _, rest) = parse_variable(rest, address_space_map);
                    (output, Op::IntAdd, [v0, v1], vec![], munch(rest))
                }
                "vmovdqu_avx" => {
                    // vmovdqu
                    let (v0, _, rest) = parse_variable(rest, address_space_map);
                    (
                        output,
                        Op::Copy,
                        [v0, Variable::Unused],
                        vec![],
                        munch(rest),
                    )
                }
                "vmovd_avx" | "vmovq_avx" => {
                    // vmovd, vmovq
                    let (v0, _, rest) = parse_variable(rest, address_space_map);
                    let (op, inps) = match v0.try_size().unwrap().cmp(&output.try_size().unwrap()) {
                        std::cmp::Ordering::Less => (Op::IntZext, [v0, Variable::Unused]),
                        std::cmp::Ordering::Equal => (Op::Copy, [v0, Variable::Unused]),
                        std::cmp::Ordering::Greater => {
                            (Op::SubPiece, [v0, Variable::Constant { value: 0, size: 1 }])
                        }
                    };
                    (output, op, inps, vec![], munch(rest))
                }
                "vpunpcklwd_avx" | "vpunpckldq_avx" | "vpunpcklqdq_avx" | "vpcmpeqb_avx2"
                | "vpcmpeqb_avx" | "vpsubb_avx2" | "vpsadbw_avx2" | "vpextrw_avx"
                | "vextracti128_avx2" | "vpshufb_avx" | "vpsrldq_avx" => {
                    // various operations that modify the output in "fun" ways
                    let (v0, _, rest) = parse_variable(rest, address_space_map);
                    let (v1, _, rest) = parse_variable(rest, address_space_map);
                    (
                        output,
                        Op::UnderspecifiedOutputModification,
                        [v0, v1],
                        vec![],
                        munch(rest),
                    )
                }
                "vpmovzxbw_avx" | "vpmovzxwd_avx" | "vpmovzxdq_avx" | "vpmovzxbw_avx2"
                | "vpmovzxwd_avx2" | "vpmovzxdq_avx2" => {
                    // more operations that modify the output in "fun" ways, but with only
                    // single input
                    let (v0, _, rest) = parse_variable(rest, address_space_map);
                    (
                        output,
                        Op::UnderspecifiedOutputModification,
                        [v0, Variable::Unused],
                        vec![],
                        munch(rest),
                    )
                }
                "vpinsrb_avx" | "vpinsrd_avx" | "vpinsrq_avx" => {
                    // various vpinsr... that appear to have a 3rd `const_v` at the end
                    let (v0, _, rest) = parse_variable(rest, address_space_map);
                    let (v1, _, rest) = parse_variable(rest, address_space_map);
                    let (const_v, _, rest) = parse_variable(rest, address_space_map);
                    assert!(matches!(const_v, Variable::Constant { .. }));
                    (
                        output,
                        Op::UnderspecifiedOutputModification,
                        [v0, v1],
                        vec![],
                        munch(rest),
                    )
                }
                "LOCK" | "UNLOCK" => {
                    // An x86 "lock". Mapping to a nop instead.
                    //
                    // XXX: Maybe we want to utilize this information somehow? We don't actually
                    // quite get the connection to the next instruction directly, so would need at
                    // least some syntactic analysis.
                    (
                        output,
                        Op::Nop,
                        [Variable::Unused, Variable::Unused],
                        vec![],
                        munch(rest),
                    )
                }

                _ => todo!("Unknown CALLOTHER code {c:#?}, rest = {rest:?}"),
            }
        }
        _ => todo!("Lifter for `{}` (rest = `{}`)", op, rest),
    }
}
