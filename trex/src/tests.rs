use crate::il::{AddressSpace, Endian, Instruction, Op, Program, Variable};
use std::rc::Rc;

#[cfg(test)]
use crate::structural::IntegerOp;

#[cfg(test)]
fn assert_unorderedset_eq<T: Eq + std::hash::Hash + Ord + std::fmt::Debug>(
    a: impl IntoIterator<Item = T>,
    b: impl IntoIterator<Item = T>,
) {
    use crate::containers::unordered::UnorderedSet;
    let a: UnorderedSet<_> = a.into_iter().collect();
    let b: UnorderedSet<_> = b.into_iter().collect();
    assert_eq!(a, b)
}

pub fn tiny_program() -> Rc<Program> {
    let as0 = AddressSpace {
        name: "ram".into(),
        endianness: Endian::Little,
        wordsize: 1,
    };
    let as1 = AddressSpace {
        name: "as1".into(),
        endianness: Endian::Little,
        wordsize: 1,
    };
    let mut prog = Program::new(vec![as0, as1]);
    prog.begin_function("tiny_program", [], 0);
    prog.add_one_machine_instruction(vec![Instruction {
        address: 0,
        op: Op::Copy,
        output: Variable::Varnode {
            address_space_idx: 0,
            offset: 0,
            size: 1,
        },
        inputs: [
            Variable::Varnode {
                address_space_idx: 1,
                offset: 1,
                size: 1,
            },
            Variable::Unused,
        ],
        indirect_targets: vec![],
    }]);
    prog.add_one_machine_instruction(vec![Instruction {
        address: 1,

        op: Op::IntSub,
        output: Variable::Varnode {
            address_space_idx: 1,
            offset: 3,
            size: 1,
        },
        inputs: [
            Variable::Varnode {
                address_space_idx: 1,
                offset: 2,
                size: 1,
            },
            Variable::Constant { value: 4, size: 1 },
        ],
        indirect_targets: vec![],
    }]);
    prog.end_function();

    Rc::new(prog)
}

#[test]
fn tiny_program_inference() {
    let prog = tiny_program();

    let types = prog.infer_structural_types();
    dbg!(&types);

    let o0 = types.ssa.get_output_impacted_variable(1).unwrap();
    let o1 = types.ssa.get_input_variable(1, 0);
    let o2 = types.ssa.get_input_variable(2, 0);
    let o3 = types.ssa.get_output_impacted_variable(2).unwrap();

    assert_ne!(o0, o1);
    assert_ne!(o0, o2);
    assert_ne!(o0, o3);
    assert_ne!(o1, o2);
    assert_ne!(o1, o3);
    assert_ne!(o2, o3);

    let i0 = types.get_type_index(o0).unwrap();
    let i1 = types.get_type_index(o1).unwrap();
    let i2 = types.get_type_index(o2).unwrap();
    let i3 = types.get_type_index(o3).unwrap();

    let t0 = types.get_type_from_index(i0).unwrap();
    let t1 = types.get_type_from_index(i1).unwrap();
    let t2 = types.get_type_from_index(i2).unwrap();
    let t3 = types.get_type_from_index(i3).unwrap();

    // We know their sizes
    assert_eq!(t0.observed_size(), Some(1));
    assert_eq!(t1.observed_size(), Some(1));
    assert_eq!(t2.observed_size(), Some(1));
    assert_eq!(t3.observed_size(), Some(1));

    // Variables at offset 0 and 1 are equal because of copy
    assert!(types.are_equal_at_indexes(i0, i1));

    // Variables at offset 2 and 3 both support subtraction
    assert!(t2.integer_ops.contains(&(IntegerOp::Sub, 1)));
    assert!(t3.integer_ops.contains(&(IntegerOp::Sub, 1)));
}

pub fn basic_program() -> Rc<Program> {
    let ram = AddressSpace {
        name: "RAM".into(),
        endianness: Endian::Little,
        wordsize: 8,
    };
    let mut prog = Program::new(vec![ram]);
    prog.begin_function("basic_program", [], 0);
    prog.add_one_machine_instruction(vec![Instruction {
        address: 0,
        op: Op::Copy,
        output: Variable::Varnode {
            address_space_idx: 0,
            offset: 0,
            size: 22,
        },
        inputs: [
            Variable::Varnode {
                address_space_idx: 0,
                offset: 456,
                size: 22,
            },
            Variable::Unused,
        ],
        indirect_targets: vec![],
    }]);
    prog.add_one_machine_instruction(vec![Instruction {
        address: 1,
        op: Op::Copy,
        output: Variable::Varnode {
            address_space_idx: 0,
            offset: 123,
            size: 22,
        },
        inputs: [
            Variable::Varnode {
                address_space_idx: 0,
                offset: 456,
                size: 22,
            },
            Variable::Unused,
        ],
        indirect_targets: vec![],
    }]);
    prog.end_function();
    Rc::new(prog)
}

#[test]
fn basic_type_inference() {
    let prog = basic_program();

    let types = prog.infer_structural_types();
    dbg!(&types);

    let v_at_456 = types.ssa.get_input_variable(1, 0);
    assert_eq!(v_at_456, types.ssa.get_input_variable(2, 0));

    let v_at_0 = types.ssa.get_output_impacted_variable(1).unwrap();
    let v_at_123 = types.ssa.get_output_impacted_variable(2).unwrap();

    // Variable at 0 and 456 have same type, because one is copied into the other
    assert!(types.are_equal_at_indexes(
        types.get_type_index(v_at_0.clone()).unwrap(),
        types.get_type_index(v_at_456).unwrap()
    ));
    // Variable at 0 and 123 have same type, because they are being written to from the same point
    assert!(types.are_equal_at_indexes(
        types.get_type_index(v_at_0.clone()).unwrap(),
        types.get_type_index(v_at_123).unwrap()
    ));

    // Let's get one of those types, referred to via an index
    let loc0 = types.get_type_index(v_at_0).unwrap();

    // We know the size of the types
    assert_eq!(
        types.get_type_from_index(loc0).unwrap().observed_size(),
        Some(22)
    );
}

pub fn basic_pointer_program() -> Rc<Program> {
    let ram = AddressSpace {
        name: "RAM".into(),
        endianness: Endian::Little,
        wordsize: 8,
    };
    let mut prog = Program::new(vec![ram]);
    prog.begin_function("basic_pointer_program", [], 0);
    prog.add_one_machine_instruction(vec![Instruction {
        address: 0,
        op: Op::Load,
        output: Variable::Varnode {
            address_space_idx: 0,
            offset: 0,
            size: 22,
        },
        inputs: [
            Variable::DerefVarnode {
                derefval_address_space_idx: 0,
                derefval_size: 22,
                addr_address_space_idx: 0,
                addr_offset: 456,
            },
            Variable::Unused,
        ],
        indirect_targets: vec![],
    }]);
    prog.add_one_machine_instruction(vec![Instruction {
        address: 1,
        op: Op::Load,
        output: Variable::Varnode {
            address_space_idx: 0,
            offset: 123,
            size: 22,
        },
        inputs: [
            Variable::DerefVarnode {
                derefval_address_space_idx: 0,
                derefval_size: 22,
                addr_address_space_idx: 0,
                addr_offset: 456,
            },
            Variable::Unused,
        ],
        indirect_targets: vec![],
    }]);
    prog.end_function();
    Rc::new(prog)
}

#[test]
fn basic_pointer_type_inference() {
    let prog = basic_pointer_program();

    let types = prog.infer_structural_types();
    dbg!(&types);

    let v_at_456 = types.ssa.get_input_variable(1, 0);
    assert_eq!(v_at_456, types.ssa.get_input_variable(2, 0));

    let v_at_0 = types.ssa.get_output_impacted_variable(1).unwrap();
    let v_at_123 = types.ssa.get_output_impacted_variable(2).unwrap();

    // ASLocation 0 and 123 have same type, because they are being written to from the same point
    assert!(types.are_equal_at_indexes(
        types.get_type_index(v_at_0.clone()).unwrap(),
        types.get_type_index(v_at_123).unwrap()
    ));

    // Let's get one of those types, referred to via an index
    let loc0 = types.get_type_index(v_at_0).unwrap();

    // We also know the size of the types
    assert_eq!(
        types.get_type_from_index(loc0).unwrap().observed_size(),
        Some(22)
    );

    // We also know that location 456 is a pointer type of the type at location 0
    let loc456 = types.get_type_index(v_at_456).unwrap();
    assert!(types
        .get_type_from_index(loc456)
        .unwrap()
        .pointer_to
        .is_some());
    assert!(types.are_equal_at_indexes(
        loc0,
        types
            .get_type_from_index(loc456)
            .unwrap()
            .pointer_to
            .unwrap()
    ));
}

pub fn linked_list_program_with_recursion_in_slot1() -> Rc<Program> {
    let ram = AddressSpace {
        name: "RAM".into(),
        endianness: Endian::Little,
        wordsize: 8,
    };
    let temp = AddressSpace {
        name: "temp".into(),
        endianness: Endian::Little,
        wordsize: 8,
    };
    let mut prog = Program::new(vec![ram, temp]);

    let var_temp = Variable::Varnode {
        address_space_idx: 1,
        offset: 0,
        size: 8,
    };
    let deref_var_temp_4 = Variable::DerefVarnode {
        addr_address_space_idx: 1,
        addr_offset: 0,
        derefval_size: 4,
        derefval_address_space_idx: 0,
    };
    let var_p = Variable::Varnode {
        address_space_idx: 0,
        offset: 0,
        size: 8,
    };
    let deref_var_p_next = Variable::DerefVarnode {
        addr_address_space_idx: 0,
        addr_offset: 0,
        derefval_size: 8,
        derefval_address_space_idx: 0,
    };
    let var_x = Variable::Varnode {
        address_space_idx: 0,
        offset: 100,
        size: 4,
    };

    // This code below is written with the assumption of the following linked list:
    //
    //  struct node {
    //     node* next;
    //     int   data;
    //  }
    //
    //  node* p;
    //  int   x;
    //
    //  node* temp;

    prog.begin_function("linked_list_program_with_recursion_in_slot1", [], 0);
    // 0: if (p->next != 0) { goto 1 } else { goto 100 }
    prog.add_one_machine_instruction(vec![
        Instruction {
            address: 0,
            op: Op::Load,
            output: var_temp.clone(),
            inputs: [deref_var_p_next, Variable::Unused],
            indirect_targets: vec![],
        },
        Instruction {
            address: 0,
            op: Op::Cbranch,
            output: Variable::Unused,
            inputs: [Variable::MachineAddress { addr: 1 }, var_temp.clone()],
            indirect_targets: vec![],
        },
        Instruction {
            address: 0,
            op: Op::Branch,
            output: Variable::Unused,
            inputs: [Variable::MachineAddress { addr: 100 }, Variable::Unused],
            indirect_targets: vec![],
        },
    ]);
    // 1: p = p->next; (equivalently, p = temp)
    prog.add_one_machine_instruction(vec![Instruction {
        address: 1,
        op: Op::Copy,
        output: var_p.clone(),
        inputs: [var_temp.clone(), Variable::Unused],
        indirect_targets: vec![],
    }]);
    // goto 0
    prog.add_one_machine_instruction(vec![Instruction {
        address: 2,
        op: Op::Branch,
        output: Variable::Unused,
        inputs: [Variable::MachineAddress { addr: 0 }, Variable::Unused],
        indirect_targets: vec![],
    }]);

    // 100: x = p->data
    prog.add_one_machine_instruction(vec![
        Instruction {
            address: 100,
            op: Op::IntAdd,
            output: var_temp,
            inputs: [var_p, Variable::Constant { value: 8, size: 8 }],
            indirect_targets: vec![],
        },
        Instruction {
            address: 100,
            op: Op::Load,
            output: var_x,
            inputs: [deref_var_temp_4, Variable::Unused],
            indirect_targets: vec![],
        },
    ]);
    prog.end_function();
    Rc::new(prog)
}

#[test]
fn linked_list_inference() {
    let prog = linked_list_program_with_recursion_in_slot1();

    let types = prog.infer_structural_types();
    dbg!(&types);

    // Get the named variables in the program
    let var_p = types.ssa.get_input_variable(1, 0);
    let var_temp1 = types.ssa.get_input_variable(2, 1);
    assert_eq!(types.ssa.get_input_variable(4, 0), var_temp1);
    assert_eq!(types.ssa.get_input_variable(6, 0), var_p);
    let var_temp2 = types.ssa.get_input_variable(7, 0);
    assert_ne!(var_temp1, var_temp2);
    assert_eq!(
        types.ssa.get_output_impacted_variable(6),
        Some(var_temp2.clone())
    );
    let var_x = types.ssa.get_output_impacted_variable(7).unwrap();

    // Get their type indices ...
    let i_p = types.get_type_index(var_p).unwrap();
    let i_temp1 = types.get_type_index(var_temp1).unwrap();
    let i_temp2 = types.get_type_index(var_temp2).unwrap();
    let i_x = types.get_type_index(var_x).unwrap();

    // ... and their types
    let t_p = types.get_type_from_index(i_p).unwrap();
    let _t_temp1 = types.get_type_from_index(i_temp1).unwrap();
    let t_temp2 = types.get_type_from_index(i_temp2).unwrap();
    let t_x = types.get_type_from_index(i_x).unwrap();

    // Get the dereferenced type
    let i_p_deref = t_p.pointer_to.unwrap();
    let _t_p_deref = types.get_type_from_index(i_p_deref).unwrap();

    // Make sure we've found the recursion
    assert!(types.are_equal_at_indexes(i_p_deref, i_temp1));
    assert!(types.are_equal_at_indexes(i_p_deref, i_p));
    assert!(types.are_equal_at_indexes(i_p, i_temp1));

    // Check all their sizes
    assert_eq!(t_p.observed_size(), Some(8)); // Don't need to check t_p_deref, t_temp1 since they are same
    assert_eq!(t_temp2.observed_size(), Some(8));
    assert_eq!(t_x.observed_size(), Some(4));

    // Make sure addition/comparison properties hold
    assert!(t_p.integer_ops.contains(&(IntegerOp::Add, 8)));
    assert!(t_p.zero_comparable);
    assert!(t_p.integer_ops.contains(&(IntegerOp::Eq, 8)));
    assert!(t_temp2.integer_ops.contains(&(IntegerOp::Add, 8)));
}

pub fn linked_list_program_with_recursion_in_slot2() -> Rc<Program> {
    let ram = AddressSpace {
        name: "RAM".into(),
        endianness: Endian::Little,
        wordsize: 8,
    };
    let temp = AddressSpace {
        name: "temp".into(),
        endianness: Endian::Little,
        wordsize: 8,
    };
    let mut prog = Program::new(vec![ram, temp]);

    let var_temp = Variable::Varnode {
        address_space_idx: 1,
        offset: 0,
        size: 8,
    };
    let deref_var_temp_8 = Variable::DerefVarnode {
        addr_address_space_idx: 1,
        addr_offset: 0,
        derefval_size: 8,
        derefval_address_space_idx: 0,
    };
    let var_p = Variable::Varnode {
        address_space_idx: 0,
        offset: 0,
        size: 8,
    };
    let deref_var_p_4 = Variable::DerefVarnode {
        addr_address_space_idx: 0,
        addr_offset: 0,
        derefval_size: 4,
        derefval_address_space_idx: 0,
    };
    let var_x = Variable::Varnode {
        address_space_idx: 0,
        offset: 100,
        size: 4,
    };

    // This code below is written with the assumption of the following linked list:
    //
    //  struct node {
    //     int   data;
    //     node* next;
    //  } // packed
    //
    //  node* p;
    //  int   x;
    //
    //  node* temp;

    prog.begin_function("linked_list_program_with_recursion_in_slot2", [], 0);
    // 0: if (p->next != 0) { goto 1 } else { goto 100 }
    prog.add_one_machine_instruction(vec![
        Instruction {
            address: 0,
            op: Op::IntAdd,
            output: var_temp.clone(),
            inputs: [var_p.clone(), Variable::Constant { value: 4, size: 8 }],
            indirect_targets: vec![],
        },
        Instruction {
            address: 0,
            op: Op::Load,
            output: var_temp.clone(),
            inputs: [deref_var_temp_8, Variable::Unused],
            indirect_targets: vec![],
        },
        Instruction {
            address: 0,
            op: Op::Cbranch,
            output: Variable::Unused,
            inputs: [Variable::MachineAddress { addr: 1 }, var_temp.clone()],
            indirect_targets: vec![],
        },
        Instruction {
            address: 0,
            op: Op::Branch,
            output: Variable::Unused,
            inputs: [Variable::MachineAddress { addr: 100 }, Variable::Unused],
            indirect_targets: vec![],
        },
    ]);
    // 1: p = p->next; (equivalently, p = temp)
    prog.add_one_machine_instruction(vec![Instruction {
        address: 1,
        op: Op::Copy,
        output: var_p,
        inputs: [var_temp, Variable::Unused],
        indirect_targets: vec![],
    }]);
    // goto 0
    prog.add_one_machine_instruction(vec![Instruction {
        address: 2,
        op: Op::Branch,
        output: Variable::Unused,
        inputs: [Variable::MachineAddress { addr: 0 }, Variable::Unused],
        indirect_targets: vec![],
    }]);

    // 100: x = p->data
    prog.add_one_machine_instruction(vec![Instruction {
        address: 100,
        op: Op::Load,
        output: var_x,
        inputs: [deref_var_p_4, Variable::Unused],
        indirect_targets: vec![],
    }]);
    prog.end_function();
    Rc::new(prog)
}

pub fn basic_mutual_recursive_types_program() -> Rc<Program> {
    let ram = AddressSpace {
        name: "RAM".into(),
        endianness: Endian::Little,
        wordsize: 8,
    };
    let temp = AddressSpace {
        name: "temp".into(),
        endianness: Endian::Little,
        wordsize: 8,
    };
    let mut prog = Program::new(vec![ram, temp]);

    /*

    struct A { B* b; int x; }
    struct B { A* a; bool y; }

    int foo(A* a, B* b) {
      while (a->b != b) {
        a = a->b->a;
      }
      return a->y;
    }

    */

    let var_a = Variable::Varnode {
        address_space_idx: 0,
        offset: 0,
        size: 8,
    };
    let var_b = Variable::Varnode {
        address_space_idx: 0,
        offset: 8,
        size: 8,
    };
    let var_t1 = Variable::Varnode {
        address_space_idx: 1,
        offset: 0,
        size: 8,
    };
    let var_t2 = Variable::Varnode {
        address_space_idx: 1,
        offset: 100,
        size: 1,
    };
    let var_ret = Variable::Varnode {
        address_space_idx: 0,
        offset: 16,
        size: 4,
    };

    let deref = |v: Variable, derefval_size: usize| match v {
        Variable::Varnode {
            address_space_idx,
            offset,
            size,
        } => {
            assert_eq!(size, 8);
            Variable::DerefVarnode {
                addr_address_space_idx: address_space_idx,
                addr_offset: offset,
                derefval_size,
                derefval_address_space_idx: 0,
            }
        }
        _ => unreachable!(),
    };

    prog.begin_function("basic_mutual_recursive_types_program", [], 0);
    prog.add_one_machine_instruction(vec![
        // if (a->b == b), jump to addr 1
        Instruction {
            address: 0,
            op: Op::Load,
            output: var_t1.clone(),
            inputs: [deref(var_a.clone(), 8), Variable::Unused],
            indirect_targets: vec![],
        },
        Instruction {
            address: 0,
            op: Op::IntEqual,
            output: var_t2.clone(),
            inputs: [var_t1.clone(), var_b],
            indirect_targets: vec![],
        },
        Instruction {
            address: 0,
            op: Op::Cbranch,
            output: Variable::Unused,
            inputs: [Variable::MachineAddress { addr: 1 }, var_t2],
            indirect_targets: vec![],
        },
        // else,
        // a = a->b->a
        Instruction {
            address: 0,
            op: Op::Load,
            output: var_a.clone(),
            inputs: [deref(var_t1.clone(), 8), Variable::Unused],
            indirect_targets: vec![],
        },
        // jump back
        Instruction {
            address: 0,
            op: Op::Branch,
            output: Variable::Unused,
            inputs: [Variable::MachineAddress { addr: 0 }, Variable::Unused],
            indirect_targets: vec![],
        },
    ]);
    prog.add_one_machine_instruction(vec![
        // x = a->x
        Instruction {
            address: 1,
            op: Op::IntAdd,
            output: var_t1.clone(),
            inputs: [var_a, Variable::Constant { value: 8, size: 8 }],
            indirect_targets: vec![],
        },
        Instruction {
            address: 1,
            op: Op::Load,
            output: var_ret,
            inputs: [deref(var_t1, 4), Variable::Unused],
            indirect_targets: vec![],
        },
    ]);
    prog.end_function();

    Rc::new(prog)
}

pub fn across_two_loads() -> Rc<Program> {
    crate::ghidra_lifter::lift_from(
        "\
PROGRAM
name across_two_loads
big_endian false

ADDRESS_SPACES
        0 ram 8

PCODE_LISTING
        00100000 loadtwiceFromSameReg
                Unaffected:
                00100000 (register, 0xaa, 8) LOAD (const, 0x0, 4) , (register, 0x80, 8)
                00100000 (register, 0xbb, 8) LOAD (const, 0x0, 4) , (register, 0x80, 8)

        00200000 loadtwiceFromCopiedSameAddr
                Unaffected:
                00200000 (register, 0x90, 8) COPY (register, 0x80, 8)
                00200000 (register, 0xaa, 8) LOAD (const, 0x0, 4) , (register, 0x80, 8)
                00200000 (register, 0xbb, 8) LOAD (const, 0x0, 4) , (register, 0x90, 8)

        00300000 loadtwiceFromSameCalculatedAddr
                Unaffected:
                00300000 (register, 0x20, 8) INT_ADD (register, 0x80, 8) , (const, 0x5, 8)
                00300000 (register, 0x30, 8) INT_ADD (register, 0x80, 8) , (const, 0x5, 8)
                00300000 (register, 0xaa, 8) LOAD (const, 0x0, 4) , (register, 0x20, 8)
                00300000 (register, 0xbb, 8) LOAD (const, 0x0, 4) , (register, 0x30, 8)
",
    )
}

#[test]
fn across_two_loads_inference() {
    let prog = across_two_loads();

    let types = prog.infer_structural_types();
    dbg!(&types);

    dbg!(types.ssa.debug_program(true, None));

    let output_at = |il_pc: usize| types.ssa.get_output_impacted_variable(il_pc).unwrap();

    let same_types_at_outputs_of_il_pcs = |pc1, pc2| {
        types.are_equal_at_indexes(
            types.get_type_index(output_at(pc1)).unwrap(),
            types.get_type_index(output_at(pc2)).unwrap(),
        )
    };

    assert!(same_types_at_outputs_of_il_pcs(1, 2));
    assert!(same_types_at_outputs_of_il_pcs(6, 7));
    assert!(same_types_at_outputs_of_il_pcs(12, 13));
}

pub fn test_program_with_name(name: &str) -> Rc<Program> {
    let mut programs: std::collections::BTreeMap<&str, fn() -> Rc<Program>> = Default::default();

    macro_rules! ins {
        () => {};
        ($f:ident) => {
            programs.insert(stringify!($f), $f);
        };
        ([$n:expr]$f:ident) => {
            programs.insert($n, $f);
        };
        ($x:tt,$($xs:tt)*) => {
            ins!($x);
            ins!($($xs)*);
        };
        ([$n:tt]$x:tt,$($xs:tt)*) => {
            ins!([$n]$x);
            ins!($($xs)*);
        };
    }
    ins!(
        tiny_program,
        basic_program,
        basic_pointer_program,
        ["linked_list_slot1"]linked_list_program_with_recursion_in_slot1,
        ["linked_list_slot2"]linked_list_program_with_recursion_in_slot2,
        ["mutual_recursion"]basic_mutual_recursive_types_program,
        across_two_loads,
    );

    let names = programs.keys().collect::<Vec<_>>();
    let mut counts = names
        .iter()
        .map(|k| {
            k.chars()
                .zip(name.chars())
                .take_while(|(a, b)| a == b)
                .count()
        })
        .collect::<Vec<_>>();
    counts.sort_unstable();
    if counts[counts.len() - 1] != name.len() {
        panic!("Invalid prefix. Expected one of {:#?}", names)
    } else if counts[counts.len() - 1] == counts[counts.len() - 2] {
        panic!("Non-unique prefix. Expected one of {:#?}", names)
    }

    let name = names
        .into_iter()
        .max_by_key(|k| {
            k.chars()
                .zip(name.chars())
                .take_while(|(a, b)| a == b)
                .count()
        })
        .unwrap();

    programs.get(name).unwrap()()
}

#[cfg(test)]
#[test]
fn c_types_for_linked_list_slot_1() {
    let prog =
        crate::ghidra_lifter::lift_from(include_str!("../tests/test-linked-list-slot1.lifted"));
    let vars = crate::ghidra_variable_lifter::lift_from(
        include_str!("../tests/test-linked-list-slot1.vars",),
        &prog,
    );
    let types = prog.infer_structural_types();
    let colocated = crate::starts_at_analysis::CoLocated::analyze(&std::rc::Rc::new(types));
    let aggregate = crate::aggregate_types::AggregateTypes::analyze(&std::rc::Rc::new(colocated));
    let structuredtypes = aggregate.to_structural_types();
    let mut serializable_types = structuredtypes.serialize(&Some(vars));
    crate::type_rounding::round_up_to_c_types(serializable_types.types_mut());
    let c_types = crate::c_type_printer::PrintableCTypes::new(&serializable_types).to_string();

    let expected = "
        // n@getlast@00100000 : t1*
        // nxt@getlast@00100000 : t1*

        struct t1 {
          t1* field_0;
          int32_t field_8;
        };";

    eprintln!("Expected:\n{}", expected);
    eprintln!("Got:\n{}", c_types);

    assert_eq!(
        c_types.split_whitespace().collect::<Vec<_>>(),
        expected.split_whitespace().collect::<Vec<_>>()
    );
}

#[cfg(test)]
#[test]
fn c_types_for_linked_list_slot_2() {
    let prog =
        crate::ghidra_lifter::lift_from(include_str!("../tests/test-linked-list-slot2.lifted"));
    let vars = crate::ghidra_variable_lifter::lift_from(
        include_str!("../tests/test-linked-list-slot2.vars",),
        &prog,
    );
    let types = prog.infer_structural_types();
    let colocated = crate::starts_at_analysis::CoLocated::analyze(&std::rc::Rc::new(types));
    let aggregate = crate::aggregate_types::AggregateTypes::analyze(&std::rc::Rc::new(colocated));
    let structuredtypes = aggregate.to_structural_types();
    let mut serializable_types = structuredtypes.serialize(&Some(vars));
    crate::type_rounding::round_up_to_c_types(serializable_types.types_mut());
    let c_types = crate::c_type_printer::PrintableCTypes::new(&serializable_types).to_string();

    let expected = "
        // n@getlast@00100000 : t1*
        // nxt@getlast@00100000 : t1*

        struct t1 {
          int32_t field_0;
          t1* field_8;
        };";

    eprintln!("Expected:\n{}", expected);
    eprintln!("Got:\n{}", c_types);

    assert_eq!(
        c_types.split_whitespace().collect::<Vec<_>>(),
        expected.split_whitespace().collect::<Vec<_>>()
    );
}
