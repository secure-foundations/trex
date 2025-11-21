//! Intermediate language to aid type inference.
//!
//! Inspired by (but distinct from) Ghidra's [P-Code intermediate
//! language](https://ghidra.re/courses/languages/html/pcoderef.html).

use crate::containers::unordered::{UnorderedMap, UnorderedMapEntry, UnorderedSet};
use crate::dataflow::ASLocation;
use crate::global_value_numbering::GlobalValueNumbering;
use crate::inference_config::CONFIG;
use crate::log::*;
use crate::ssa::SSA;
use crate::structural::{BooleanOp, FloatOp, IntegerOp, StructuralTypes};
use std::rc::Rc;

/// An IL operation that operates on [`Variable`]s.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Op {
    /// Boolean AND; despite being size 1, it is interpreted only as true or false
    BoolAnd,
    /// Boolean logical negation; despite being size 1, it is interpreted only as true or false
    BoolNegate,
    /// Boolean OR; despite being size 1, it is interpreted only as true or false
    BoolOr,
    /// Boolean XOR; despite being size 1, it is interpreted only as true or false
    BoolXor,
    /// Unconditional branch to `input0`
    Branch,
    /// Branch to (in original address space) the indirect offset `input0`
    BranchIndOffset,
    /// Semantically equivalent to [`Op::Branch`], branching to `input0`; only difference is
    /// intention, with this instruction showing that it was originally part of a "call" as the
    /// underlying architecture-level instruction. The callee _may_ return back to the fallthrough
    /// code after this instruction. If the fallthrough cannot be executed, see
    /// [`Self::CallWithNoFallthrough`].
    CallWithFallthrough,
    /// A `Call` instruction jumping to a function that does no return. See
    /// [`Self::CallWithFallthrough`] for a function that can return.
    CallWithNoFallthrough,
    /// An indirect call, branching (in original address space) to the indirect offset
    /// `input0`. Semantically equivalent to [`Op::BranchIndOffset`]. See
    /// [`Op::CallWithFallthrough`] for fallthrough details.
    CallWithFallthroughIndirect,
    /// An indirect call, branching (in original address space) to the indirect offset
    /// `input0`. Semantically equivalent to [`Op::BranchIndOffset`]. See
    /// [`Op::CallWithNoFallthrough`] for fallthrough details.
    CallWithNoFallthroughIndirect,
    /// A conditional branch to `input0` taken iff `input1` is non-zero
    Cbranch,
    /// Copy a sequence of contiguous bytes from `input0` to `output`
    Copy,
    // Cpoolref,
    /// Convert a float to a float of a different size `output = input`; if output is smaller in
    /// size, this may lose precision.
    Float2Float,
    /// Floating `input0` to (signed) integer via truncation. Rounding is towards 0.
    Float2IntTrunc,
    /// Floating absolute value operator `|input0|`
    FloatAbs,
    /// Floating sum `input0 + input1`
    FloatAdd,
    // FloatCeil,
    /// Floating division `input0 / input1`
    FloatDiv,
    // FloatFloor,
    /// Floating comparison `input0 == input1`
    FloatEqual,
    /// Floating comparison `input0 != input1`
    FloatNotEqual,
    /// Floating comparison `input0 < input1`
    FloatLess,
    /// Floating comparison `input0 <= input1`
    FloatLessEqual,
    /// Floating comparison `is_nan(input0)`
    FloatIsNan,
    /// Floating multiplication `input0 * input1`
    FloatMult,
    /// Floating point negation `-input0`
    FloatNeg,
    /// Floating rounding `round(input0)`, towards nearest integer; this does *not* convert float to
    /// int, but instead rounds a float and returns a float.
    FloatRound,
    /// Floating square root `sqrt(input0)`
    FloatSqrt,
    /// Floating subtraction `input0 - input1`
    FloatSub,
    /// An integer to floating-point conversion. `input0` viewed as a signed integer is converted to
    /// floating-point format and stored in `output`. `input0` and `output` need not be the same
    /// size.
    Int2Float,
    /// Wrapping sum of `input0` and `input1`
    IntAdd,
    /// Bitwise AND of `input0` and `input1`
    IntAnd,
    /// Check for unsigned addition carry for `input0 + input1`
    IntCarry,
    /// Check if `input0 == input1`
    IntEqual,
    /// Check if `input0 != input1`
    IntNotEqual,
    /// Unsigned integer comparison `input0 u< input1`
    IntLess,
    // IntLessequal,
    /// Wrapping multiplication of `input0` and `input1`
    IntMult,
    /// Bitwise OR or `input0` and `input1`
    IntOr,
    /// Check for signed subtraction borrow for `input0 - input1`. Note that equivalent condition
    /// for unsigned borrow is [`Op::IntLess`]
    IntSBorrow,
    /// Check for signed addition carry for `input0 + input1`
    IntSCarry,
    /// Unsigned integer division `input0 u/ input1`
    IntUDiv,
    /// Signed integer division `input0 s/ input1`
    IntSDiv,
    /// Unsigned integer remainder `input0 u% input1`
    IntURem,
    /// Signed integer remainder `input0 s% input1`
    IntSRem,
    /// Sign-extend `input0`
    IntSext,
    /// Signed integer comparison `input0 s< input1`
    IntSLess,
    // IntSlessequal,
    /// Left shift `input0 << input1`
    IntLeftShift,
    /// Unsigned right shift `input0 u>> input1` (aka logical right shift)
    IntURightShift,
    /// Signed right shift `input0 s>> input1` (aka arithmetic right shift)
    IntSRightShift,
    /// Wrapping subtraction `input0 - input1`
    IntSub,
    /// One's complement of `input0` (i.e., bitwise NOT)
    IntOnesComp,
    /// Two's complement of `input0`
    IntTwosComp,
    /// Bitwise XOR of `input0` and `input1`
    IntXor,
    /// Zero-extend `input0`
    IntZext,
    /// Load from `input0` (must be [`Variable::DerefVarnode`])
    Load,
    // New,
    /// Count the number of 1-bits in `input0`
    Popcount,
    /// Semantically equivalent to [`Op::BranchIndOffset`], returning to address at indirect offset
    /// `input0`; only difference is intention with this instruction showing that it was originally
    /// part of a "return" as the underlying architecture-level instruction.
    Return,
    /// Store `input1` into `input0` (must be [`Variable::DerefVarnode`])
    Store,
    /// Concatenate the bits of `input0` and `input1`, such that `input0` is the most-significant
    /// part of output. This operator understands endianness of data. Output size is the sum of
    /// input sizes.
    Piece,
    /// Truncate `input0 u>> input1` to fit into the output. This operator understands endianness of
    /// data. `input1` is a constant that specifies the number of least-significant bits to remove;
    /// any most-significant bits that don't fit into output size are ignored.
    SubPiece,
    // Userdefined,
    /// Sentinel instruction marking the start of a function. `input0` points to the first
    /// instruction of the function.
    FunctionStart,
    /// Sentinel instruction marking the end of a function
    FunctionEnd,
    /// A no-op, causes simple fallthrough to next IL instruction
    Nop,
    /// Throw a processor exception, halting all execution. No fallthrough.
    ProcessorException,
    /// Scalar operation on the lower part of a vector
    /// register. `lowerNbits(output) == Op(lowerNbits(input0),
    /// lowerNbits(input1))`
    ScalarLowerOp(u8, VectorScalarOp),
    /// Scalar operation on the upper part of a vector
    /// register. `lowerNbits(output) == Op(upperNbits(input0),
    /// upperNbits(input1))`
    ScalarUpperOp(u8, VectorScalarOp),
    /// Scalar operation on each scalar sub-portion of a vector
    /// register. For each scalar n bits of vector, `output[...n
    /// bits...] == Op(input0[...n bits...], input1[...n bits...])`
    PackedVectorOp(u8, VectorScalarOp),
    /// Map weird (non-control flow) instructions to this when
    /// lifting; this instruction marks the output as havoc'd with an
    /// underspecified operation that may or may not depend on its
    /// inputs. Completely ignores the inputs, and marks the output as
    /// non-deterministically modified each time it is executed (thus
    /// can safely be used to even model, say, x86's `RDRAND`).
    UnderspecifiedOutputModification,
    /// Map weird (non-control flow) instructions to this, when there is no output operation done,
    /// yet there are inputs to it (this can be used to safely model, say, x86's `OUT`).
    UnderspecifiedNoOutput,
}

/// An IL vector operation that operates on scalar sub-parts of
/// [`Variable`]s.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum VectorScalarOp {
    FloatAdd,
    FloatSub,
    FloatMul,
    FloatDiv,
    LogicalShiftLeft,
}

/// An input to or output from an [`Op`].
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variable {
    /// An unused input/output for the relevant op.
    // Note: We use this rather than an `Option<Variable>` at every
    // use case to keep pattern matching cleaner.
    Unused,
    /// An untyped contiguous sequence of bytes in some address space
    /// that can be treated as a single value. The operation on the
    /// variable determines its interpretation.
    Varnode {
        /// An index into the program's address spaces
        address_space_idx: usize,
        /// An offset into the address space
        offset: usize,
        /// The size of the variable
        size: usize,
    },
    /// An untyped contiguous sequence of bytes in some address space referred to by an address from
    /// a (potentially different) address space. Must only be used with [`Op::Load`] and
    /// [`Op::Store`] as their 0th operand.
    DerefVarnode {
        /// An index into the program's address spaces, where the dereferenced value lives.
        derefval_address_space_idx: usize,
        /// The size of the dereferenced value
        derefval_size: usize,
        /// An index into the program's address spaces, where the address of the value lives.
        addr_address_space_idx: usize,
        /// An offset into the address space, where the address of the value lives.
        addr_offset: usize,
    },
    /// Constant or "immediate" value
    Constant { value: u64, size: usize },
    /// An original processor address. Refers to the first [`Op`] with
    /// this particular address.
    MachineAddress { addr: u64 },
    /// An IL address. Refers directly to the particular offset in
    /// question.
    ILAddress { addr: usize },
    /// An IL offset. Refers to an offset from the IL address
    /// currently executing IL instruction.
    ILOffset { offset: isize },
    /// An offset into the stack. Should be used sparingly, only for referring to "interesting"
    /// variables for output, and not for actual lifting or type recovery by itself
    StackVariable { stack_offset: i64, var_size: usize },
}

impl Variable {
    pub fn try_size(&self) -> Option<usize> {
        match self {
            Variable::Unused
            | Variable::ILAddress { .. }
            | Variable::ILOffset { .. }
            | Variable::MachineAddress { .. } => None,
            Variable::Constant { size, .. } => Some(*size),
            Variable::Varnode { size, .. } => Some(*size),
            Variable::DerefVarnode { .. } => {
                // Should not use `size` on DerefVarnode. Get the address or derefval size directly
                // instead.
                None
            }
            Variable::StackVariable { .. } => {
                // Should not use `size`, and should get it directly instead
                None
            }
        }
    }

    pub fn try_to_aslocation(&self) -> Option<ASLocation> {
        match self {
            Variable::Unused
            | Variable::ILAddress { .. }
            | Variable::ILOffset { .. }
            | Variable::MachineAddress { .. }
            | Variable::Constant { .. } => None,
            Variable::Varnode {
                address_space_idx,
                offset,
                size: _,
            } => Some(ASLocation {
                address_space_idx: *address_space_idx,
                offset: *offset,
            }),
            Variable::DerefVarnode {
                derefval_address_space_idx: _,
                derefval_size: _,
                addr_address_space_idx,
                addr_offset,
            } => {
                // Points to the address's location. Dereferenced value is ignored.
                Some(ASLocation {
                    address_space_idx: *addr_address_space_idx,
                    offset: *addr_offset,
                })
            }
            Variable::StackVariable { .. } => {
                // Should not be used internally anyways
                None
            }
        }
    }

    pub fn is_used(&self) -> bool {
        !matches!(self, Variable::Unused)
    }

    fn to_aslocation(&self) -> ASLocation {
        self.try_to_aslocation().unwrap()
    }

    pub fn machine_addr_to_il_if_possible(&self, program: &Program) -> Self {
        match self {
            Variable::MachineAddress { addr } => {
                if let Some(&(addr, _)) = program.address_mapping.get(addr) {
                    Variable::ILAddress { addr }
                } else {
                    self.clone()
                }
            }
            _ => self.clone(),
        }
    }
}

impl std::fmt::Debug for Variable {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Variable::*;
        match self {
            Unused => write!(f, "Unused"),
            Varnode {
                address_space_idx,
                offset,
                size,
            } => write!(
                f,
                "Varnode{{as={}, off={}, sz={}}}",
                address_space_idx, offset, size
            ),
            DerefVarnode {
                derefval_address_space_idx,
                derefval_size,
                addr_address_space_idx,
                addr_offset,
            } => write!(
                f,
                "Deref@{},sz={}{{as={}, off={}}}",
                derefval_address_space_idx, derefval_size, addr_address_space_idx, addr_offset
            ),
            Constant { value, size } => {
                if f.alternate() {
                    write!(f, "${:#x}u{}", value, size)
                } else {
                    write!(f, "${:}u{}", value, size)
                }
            }
            MachineAddress { addr } => write!(f, "MCA({:#x?})", addr),
            ILAddress { addr } => write!(f, "ILA({})", addr),
            ILOffset { offset } => write!(f, "ILO({:+})", offset),
            StackVariable {
                stack_offset,
                var_size,
            } => write!(f, "STACKVAR{{off={:#x},sz={}}}", stack_offset, var_size),
        }
    }
}

/// Endianness
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endian {
    Big,
    Little,
}

/// Description of a specific address space.
#[derive(Debug, Clone)]
pub struct AddressSpace {
    /// A name for the address-space.
    pub name: String,
    /// Whether the address space is little- or big-endian.
    pub endianness: Endian,
    /// Size of a word in this address space. Only impacts [`Op::Load`]
    /// and [`Op::Store`].
    pub wordsize: usize,
}

/// An IL instruction.
///
/// Original processor instructions may be translated to one or more
/// IL instructions.
#[derive(Clone, PartialEq, Eq)]
pub struct Instruction {
    /// The address of the original processor instruction this
    /// instruction was translated from.
    pub address: u64,
    /// The actual operation performed by the instruction. This
    /// dictates the number of `inputs` and whether or not there is
    /// any `output`.
    pub op: Op,
    /// The outputs of the instruction. If it produces no output, must
    /// be set to [`Variable::Unused`].
    pub output: Variable,
    /// The inputs to the instruction. Any unused inputs must be set
    /// to [`Variable::Unused`].
    ///
    /// The number of inputs allowed is set to maximum number of
    /// inputs ever seen when lifting to the IL, and can be increased
    /// if necessary. It is kept as a fixed size array rather than a
    /// [`Vec`] to support more convenient pattern matching, as well
    /// as reducing overall heap allocation pressure. Could
    /// potentially be changed to a [`Vec`] at a later point too if
    /// necessary.
    pub inputs: [Variable; 2],
    /// The indirect jump targets. Only valid for indirect call and indirect branch instructions.
    pub indirect_targets: Vec<Variable>,
}

impl std::fmt::Debug for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Instruction {{ addr: {:#x}, op: {:?}, output: {:?}, inputs: {:?}, indtgts: {:?} }}",
            self.address, self.op, self.output, self.inputs, self.indirect_targets
        )
    }
}

impl Instruction {
    /// Confirms the validity of the instruction. Panics if invalid.
    fn confirm_valid(&self) {
        self.try_confirm_valid().unwrap()
    }

    /// Confirms the validity of the instruction.
    pub fn try_confirm_valid(&self) -> Result<(), String> {
        macro_rules! exp {
            (__fail $e:expr => [$failpats:tt]) => {{
                return Err(format!(
                    "Got {} {:?} for operation {:?}. Expected {}. Address: {:#x}.",
                    stringify!($e),
                    $e,
                    self.op,
                    stringify!($failpats),
                    self.address,
                ));
            }};
            (__fail $e:expr => [$($failpats:tt)*]) => {{
                return Err(format!(
                    "Got {} {:?} for operation {:?}. Expected one of [{}]. Address: {:#x}.",
                    stringify!($e),
                    $e,
                    self.op,
                    stringify!($($failpats)*),
                    self.address,
                ));
            }};
            (__internal $e:expr => [$pat:pat] [$($failpats:tt)*]) => {
                match $e {
                    $pat => (),
                    _ => exp!(__fail $e => [$($failpats)* $pat]),
                }
            };
            (__internal $e:expr => [$pat:pat, $($pats:pat),*] [$($failpats:tt)*]) => {
                match $e {
                    $pat => (),
                    _ => exp!(__internal $e => [$($pats),*] [$($failpats)* $pat]),
                }
            };
            (__same_size $e:expr, $f:expr) => {
                match ($e.try_size(), $f.try_size()) {
                    (Some(sz1), Some(sz2)) =>
                        if sz1 != sz2 {
                            return Err(format!(
                                "Got unequal sizes {} and {} for {} and {} operation {:?}",
                                sz1, sz2, stringify!($e), stringify!($f), self.op));
                        },
                    _ => (),
                }
            };
            (__size_lt $e:expr, $f:expr) => {
                match ($e.try_size(), $f.try_size()) {
                    (Some(sz1), Some(sz2)) =>
                        if !(sz1 < sz2) {
                            return Err(format!(
                                "Got invalid sizes {} and {} for {} and {} operation {:?}",
                                sz1, sz2, stringify!($e), stringify!($f), self.op));
                        },
                    _ => (),
                }
            };
            (__size_sum $e:expr, $f:expr, $g:expr) => {
                match ($e.try_size(), $f.try_size(), $g.try_size()) {
                    (Some(sz1), Some(sz2), Some(sz3)) =>
                        if sz1 + sz2 != sz3 {
                            return Err(format!(
                                "Expected {}+{}=={}. Got {}+{} and {} for operation {:?}",
                                stringify!($e), stringify!($f), stringify!($g),
                                sz1, sz2, sz3, self.op));
                        },
                    _ => (),
                }
            };
            (__ref i0) => { self.inputs[0] };
            (__ref i1) => { self.inputs[0] };
            (__ref o) => { self.output };
            (_m $e:expr => [0]) => { exp!(__internal $e => [Variable::Unused] []) };
            (_m $e:expr => [vn]) => { exp!(__internal $e => [Variable::Varnode {..}] []) };
            (_m $e:expr => [vnc]) => { exp!(__internal $e => [Variable::Varnode {..}, Variable::Constant{..}] []) };
            (_m $e:expr => [vnc0]) => { exp!(__internal $e => [Variable::Varnode {..}, Variable::Constant{..} | Variable::Unused] []) };
            (_m $e:expr => [c]) => { exp!(__internal $e => [Variable::Constant{..}] []) };
            (_m $e:expr => [dr]) => { exp!(__internal $e => [Variable::DerefVarnode {..}] []) };
            (_m $e:expr => [pc]) => { exp!(__internal $e => [Variable::MachineAddress {..}, Variable::ILAddress {..}, Variable::ILOffset {..}] []) };
            ($ti0:tt $ti1:tt $to:tt) => {{
                exp!(_m self.inputs[0] => [$ti0]);
                exp!(_m self.inputs[1] => [$ti1]);
                exp!(_m self.output => [$to]);
            }};
            (szeq($a:tt,$b:tt) $($rest:tt)*) => {{
                exp!($($rest)*);
                exp!(__same_size exp!(__ref $a), exp!(__ref $b));
            }};
            (szlt($a:tt,$b:tt) $($rest:tt)*) => {{
                exp!($($rest)*);
                exp!(__size_lt exp!(__ref $a), exp!(__ref $b));
            }};
            (szsum($a:tt+$b:tt==$c:tt) $($rest:tt)*) => {{
                exp!($($rest)*);
                exp!(__size_lt exp!(__ref $a), exp!(__ref $c));
                exp!(__size_lt exp!(__ref $b), exp!(__ref $c));
                exp!(__size_sum exp!(__ref $a), exp!(__ref $b), exp!(__ref $c));
            }};
            (sz($a:tt,$b:literal) $($rest:tt)*) => {{
                exp!($($rest)*);
                if exp!(__ref $a).try_size() != Some($b) {
                    return Err(format!(
                        "Got size {:?} for {} in operation {:?}. Expected {}",
                        exp!(__ref $a).try_size(), stringify!(exp!(__ref $a)),
                        self.op,
                        $b));
                }
            }};
            // Dump an error if we (for some reason) don't match anything
            ($($t:tt)*) => {
                compile_error!(concat!($(stringify!($t), " "),*))
            };
        }
        match self.op {
            Op::CallWithFallthroughIndirect
            | Op::CallWithNoFallthroughIndirect
            | Op::BranchIndOffset => {}
            _ => {
                if !self.indirect_targets.is_empty() {
                    return Err(format!(
                        "Got indirect targets {:?} for operation {:?}",
                        self.indirect_targets, self.op
                    ));
                }
            }
        }
        match self.op {
            Op::Branch | Op::CallWithFallthrough | Op::CallWithNoFallthrough => exp!(pc 0 0),
            Op::BranchIndOffset
            | Op::Return
            | Op::CallWithFallthroughIndirect
            | Op::CallWithNoFallthroughIndirect => exp!(vn 0 0),
            Op::Cbranch => {
                // Some binaries seem to actually have constant-branching conditionals
                // so we need to allow constants here too. Ideally, we could fold
                // away such Cbranches to actual Branches.
                // XXX: Missed optimization opportunity.
                exp!(pc vnc 0)
            }
            Op::Copy => exp!(szeq(i0,o) vnc 0 vn),
            Op::BoolNegate => exp!(szeq(i0,o) sz(o,1) vnc 0 vn),
            Op::FloatAdd | Op::FloatSub | Op::FloatMult | Op::FloatDiv => {
                exp!(szeq(i0,i1) szeq(i0,o) vnc vnc vn)
            }
            Op::Int2Float | Op::Float2IntTrunc => exp!(vnc 0 vn),
            Op::Float2Float => exp!(vnc 0 vn),
            Op::FloatRound | Op::FloatNeg | Op::FloatAbs | Op::FloatSqrt => {
                exp!(szeq(o,i0) vnc 0 vn)
            }
            Op::IntAdd
            | Op::IntSub
            | Op::IntMult
            | Op::IntAnd
            | Op::IntOr
            | Op::IntXor
            | Op::IntUDiv
            | Op::IntURem
            | Op::IntSDiv
            | Op::IntSRem => {
                exp!(szeq(i0,i1) szeq(i0,o) vnc vnc vn)
            }
            Op::BoolAnd | Op::BoolOr | Op::BoolXor => {
                exp!(szeq(i0,i1) szeq(i0,o) sz(o,1) vnc vnc vn)
            }
            Op::IntEqual
            | Op::IntNotEqual
            | Op::IntCarry
            | Op::IntSCarry
            | Op::IntSBorrow
            | Op::IntSLess
            | Op::IntLess
            | Op::FloatEqual
            | Op::FloatNotEqual
            | Op::FloatLess
            | Op::FloatLessEqual => {
                exp!(szeq(i0,i1) sz(o,1) vnc vnc vn)
            }
            Op::FloatIsNan => exp!(sz(o,1) vnc 0 vn),
            Op::IntLeftShift | Op::IntURightShift | Op::IntSRightShift => {
                exp!(szeq(i0,o) vnc vnc vn)
            }
            Op::IntOnesComp | Op::IntTwosComp => exp!(szeq(i0,o) vnc 0 vn),
            Op::Popcount => exp!(vnc 0 vn),
            Op::IntZext | Op::IntSext => exp!(szlt(i0,o) vnc 0 vn),
            Op::Piece => exp!(szsum(i0+i1==o) vnc vnc vn),
            Op::SubPiece => exp!(szlt(o,i0) vnc vnc vn),
            Op::Load => exp!(dr 0 vn),
            Op::Store => exp!(dr vnc 0),
            Op::FunctionStart => exp!(pc 0 0),
            Op::FunctionEnd | Op::Nop | Op::ProcessorException => exp!(0 0 0),
            Op::ScalarLowerOp(n, vsop)
            | Op::ScalarUpperOp(n, vsop)
            | Op::PackedVectorOp(n, vsop) => {
                match vsop {
                    VectorScalarOp::FloatAdd
                    | VectorScalarOp::FloatSub
                    | VectorScalarOp::FloatMul
                    | VectorScalarOp::FloatDiv => {
                        exp!(szeq(o,i0) szeq(o,i1) vnc vnc vn);
                    }
                    VectorScalarOp::LogicalShiftLeft => {
                        exp!(szeq(o,i0) vnc vnc vn);
                    }
                };
                if self.output.try_size().unwrap() <= n.into() {
                    return Err(format!(
                        "Vector operation uses size {} operands, \
                             but has scalar op of size {}",
                        self.output.try_size().unwrap(),
                        n,
                    ));
                }
                if self.output.try_size().unwrap() % usize::from(n) != 0 {
                    return Err(format!(
                        "Vector operation uses size {} operands, which is \
                             not a multiple of scalar op of size {}",
                        self.output.try_size().unwrap(),
                        n,
                    ));
                }
            }
            Op::UnderspecifiedOutputModification => exp!(vnc0 vnc0 vn),
            Op::UnderspecifiedNoOutput => exp!(vnc0 vnc0 0),
        };
        Ok(())
    }
}

/// The actual program
#[derive(Debug)]
pub struct Program {
    /// Pre-defined address-spaces in the program.
    pub address_spaces: Vec<AddressSpace>,
    /// The actual executable instructions.
    pub instructions: Vec<Instruction>,
    /// Mapping of original processor addresses to a contiguous range of IL `instructions`,
    /// represented by an offset and length. Sentinel instructions [`Op::FunctionStart`] and
    /// [`Op::FunctionEnd`] are not included in this mapping.
    address_mapping: UnorderedMap<u64, (usize, usize)>,
    /// List of basic blocks, where each basic block is a list of indexes into the
    /// instructions. Basic blocks need not be maximal.
    pub basic_blocks: Vec<Vec<usize>>,
    /// List of functions in the program, where each function is a set of basic block indexes. Each
    /// function contains exactly one [`Op::FunctionStart`] and one [`Op::FunctionEnd`]. Each
    /// function also holds on to the list of variables that are unaffected by a call to it, and its
    /// entry point (as a machine address `u64`, as well as an IL PC `usize` pointing at its
    /// `FunctionStart`).
    pub functions: Vec<(
        String,
        UnorderedSet<Variable>,
        UnorderedSet<usize>,
        (u64, usize),
    )>,
    /// Size of a pointer in this program. Usually would be either 4 or 8, for 32-bit and 64-bit
    /// programs respectively.
    pub pointer_size: usize,
    /// Auxiliary data for stack pointer fixups (see
    /// [`CONFIG::stack_pointer_patch_after_call_fallthrough`]); contains stack pointer, as well as
    /// (machine-address) targets for calls that require marking the stack pointer as unaffected.
    ///
    /// Invariant: is `Some(_)` only if `CONFIG::stack_pointer_patch_after_call_fallthrough` is `true`.
    aux_data_for_stack_pointer_fixups: Option<(Variable, UnorderedSet<u64>)>,
    /// Comments on machine instructions, used only for debugging purposes
    pub machine_insn_comments: UnorderedMap<u64, String>,
}

impl Program {
    /// Build a new empty program with the allowed address spaces
    pub fn new(address_spaces: Vec<AddressSpace>) -> Self {
        let pointer_size = {
            assert!(!address_spaces.is_empty());
            if address_spaces.len() == 1 {
                address_spaces[0].wordsize
            } else {
                let ps = address_spaces
                    .iter()
                    .filter(|a| a.name == "ram" || a.name == "RAM")
                    .map(|a| a.wordsize)
                    .collect::<Vec<_>>();
                assert_eq!(ps.len(), 1);
                ps[0]
            }
        };
        Self {
            address_spaces,
            instructions: Vec::new(),
            address_mapping: Default::default(),
            basic_blocks: Vec::new(),
            functions: Vec::new(),
            pointer_size,
            aux_data_for_stack_pointer_fixups: None,
            machine_insn_comments: Default::default(),
        }
    }

    /// Begin adding instructions for a new function with name `f`, starting at machine address
    /// `addr`, which does not affect any variables in the given `unaffected` list when a call is
    /// made to it. Specifically, this means that the variables in `unaffected` are callee-saved.
    ///
    /// Note that this is not added to `Self::address_mapping` since it is a sentinel.
    ///
    /// Also note that no sanity checking is (currently) done on the `unaffected` list. If this list
    /// is invalid, then results of later analyses can be badly unspecified.
    pub fn begin_function(
        &mut self,
        f: impl Into<String>,
        unaffected: impl IntoIterator<Item = Variable>,
        entry_point: u64,
    ) {
        if let Some(prev_func) = self.functions.last() {
            let mut end_seen_in_prev_function = false;
            'bb: for &bb in &prev_func.2 {
                for &ins in &self.basic_blocks[bb] {
                    if let Op::FunctionEnd = self.instructions[ins].op {
                        end_seen_in_prev_function = true;
                        break 'bb;
                    }
                }
            }
            assert!(
                end_seen_in_prev_function,
                "Should have called `end_function` before calling `begin_function` again"
            );
        }
        let ins = Instruction {
            address: u64::MAX,
            op: Op::FunctionStart,
            output: Variable::Unused,
            inputs: [Variable::ILOffset { offset: 1 }, Variable::Unused],
            indirect_targets: vec![],
        };
        ins.confirm_valid();
        let fn_start = self.instructions.len();
        self.instructions.push(ins);
        let fn_start_bb = self.basic_blocks.len();
        self.basic_blocks.push(vec![fn_start]);
        self.functions.push((
            f.into(),
            unaffected.into_iter().collect(),
            std::iter::once(fn_start_bb).collect(),
            (entry_point, fn_start),
        ));
    }

    /// End adding instructions for the current function. Expected to be called before the next
    /// [`Self::begin_function`].
    pub fn end_function(&mut self) {
        assert!(!self.functions.is_empty());
        let ins = Instruction {
            address: u64::MAX,
            op: Op::FunctionEnd,
            output: Variable::Unused,
            inputs: [Variable::Unused, Variable::Unused],
            indirect_targets: vec![],
        };
        ins.confirm_valid();

        // If any instructions were added, make sure that the entry point is within bounds; if none
        // were added, this is an external function, which means that the "ILO(+1)" takes care of
        // pointing it to the function end.
        if self.functions.last().unwrap().2.len() > 1 {
            let fn_start_locs = self
                .functions
                .last()
                .unwrap()
                .2
                .iter()
                .flat_map(|&bbi| self.basic_blocks[bbi].iter())
                .filter(|&&i| self.instructions[i].op == Op::FunctionStart)
                .map(|&i| &self.instructions[i].inputs[0])
                .collect::<Vec<_>>();
            assert_eq!(fn_start_locs.len(), 1);
            let fn_start_loc = fn_start_locs[0];
            match fn_start_loc {
                Variable::ILAddress { .. } => {
                    // Must've been set by an instruction as part of `add_one_machine_instruction`
                }
                _ => {
                    panic!(
                        "Weird, function entry for {} is not within bounds. Got {:?}",
                        self.functions.last().unwrap().0,
                        fn_start_loc,
                    );
                }
            }
        }

        let fn_end = self.instructions.len();
        self.instructions.push(ins);
        let fn_end_bb = self.basic_blocks.len();
        self.basic_blocks.push(vec![fn_end]);
        self.functions.last_mut().unwrap().2.insert(fn_end_bb);
    }

    /// Add the IL `instructions` for a new machine-level instruction.
    ///
    /// Makes sure internal invariants are satisfied.
    ///
    /// Performs a few sanity checks to make sure lifting is happening
    /// properly. Will panic if any sanity checks fail.
    pub fn add_one_machine_instruction(&mut self, instructions: Vec<Instruction>) {
        // Confirm that a function has been started
        assert!(!self.functions.is_empty());

        // Confirm all in same machine instruction
        assert!(!instructions.is_empty(), "Expected some IL instructions.");
        let addr = instructions[0].address;
        assert!(
            instructions.iter().all(|i| i.address == addr),
            "Not all provided IL instructions correspond to a single machine \
             instruction. Got: {:?}",
            instructions
        );

        // Make sure the instruction didn't exist before; and add a
        // mapping to it.
        let il_addr = self.instructions.len();
        if let Some(&(existing_il_addr, existing_il_len)) = self.address_mapping.get(&addr) {
            panic!(
                "Instruction at address {:x} was already added earlier. \
                 Old IL instructions at {} are {:?}. \
                 Trying to insert, at {}, new IL instructions {:?}",
                addr,
                existing_il_addr,
                &self.instructions[existing_il_addr..existing_il_addr + existing_il_len],
                il_addr,
                instructions
            );
        } else {
            self.address_mapping
                .insert(addr, (il_addr, instructions.len()));
        }

        // Confirm all instructions are valid
        instructions.iter().for_each(|i| i.confirm_valid());

        // Make sure there are no absolute `ILAddress` variables being
        // used.
        //
        // TODO: Consider if we should translate `ILOffset`s and
        // `MachineAddress` to `ILAddress` here, or as a separate
        // "cleanup"/"finalize" phase.
        for ins in &instructions {
            assert!(
                !ins.inputs
                    .iter()
                    .chain(std::iter::once(&ins.output))
                    .any(|x| matches!(x, Variable::ILAddress { .. })),
                "Unexpected use of `ILAddress` in IL instruction {:?}",
                ins
            );
        }

        // If we are at the function entry point, then set the function start to jump to here
        if addr == self.functions.last().unwrap().3 .0 {
            let fn_starts = self
                .functions
                .last()
                .unwrap()
                .2
                .iter()
                .flat_map(|&bbi| self.basic_blocks[bbi].iter())
                .filter(|&&i| self.instructions[i].op == Op::FunctionStart)
                .collect::<Vec<_>>();
            assert_eq!(fn_starts.len(), 1);
            let cur_il_addr = self.instructions.len();
            let fn_start_idx = *fn_starts[0];
            let fn_start = &mut self.instructions[fn_start_idx];
            fn_start.inputs[0] = Variable::ILAddress { addr: cur_il_addr };
        }

        // Set up basic blocks; we currently do the easy thing and generate trivial basic blocks,
        // consisting of one instruction each.
        //
        // Also, add the added basic blocks to the current function.
        //
        // TODO: Consider building better basic blocks
        {
            let ins_start = self.instructions.len();
            let bb_start = self.basic_blocks.len();
            self.basic_blocks
                .extend((0..instructions.len()).map(|i| vec![ins_start + i]));
            self.functions
                .last_mut()
                .unwrap()
                .2
                .extend(bb_start..self.basic_blocks.len());
        }

        // Finally, add all the instructions in
        let mut instructions = instructions;
        self.instructions.append(&mut instructions);
    }

    /// Get the IL addresses for a machine address
    pub fn get_il_addrs_for_machine_addr(&self, machine_addr: u64) -> Option<(usize, usize)> {
        self.address_mapping.get(&machine_addr).cloned()
    }

    /// Get the potential next instructions after instruction at IL address `il_addr`
    pub fn get_successor_instruction_addresses_for(&self, il_addr: usize) -> Vec<usize> {
        let ins = &self.instructions[il_addr];

        let input_to_addr = |input: &Variable| {
            Some(match input {
                Variable::Unused
                | Variable::Varnode { .. }
                | Variable::DerefVarnode { .. }
                | Variable::Constant { .. }
                | Variable::StackVariable { .. } => {
                    unreachable!()
                }
                Variable::MachineAddress { addr } => self.address_mapping.get(addr)?.0,
                Variable::ILAddress { addr } => *addr,
                Variable::ILOffset { offset } => {
                    let v = (il_addr as isize + offset) as usize;
                    if v < self.instructions.len() {
                        v
                    } else {
                        unreachable!(
                            "IL offset {offset} leads to out of bounds v={v} len={0}",
                            self.instructions.len()
                        )
                    }
                }
            })
        };

        let fallthrough = if il_addr + 1 < self.instructions.len() {
            vec![il_addr + 1]
        } else {
            vec![]
        };

        match ins.op {
            Op::Branch => {
                if let Some(addr) = input_to_addr(&ins.inputs[0]) {
                    vec![addr]
                } else {
                    vec![]
                }
            }
            Op::CallWithFallthrough | Op::CallWithFallthroughIndirect => {
                // We do not include the callee, to allow for convenient intra-function analysis.
                fallthrough
            }
            Op::CallWithNoFallthrough | Op::CallWithNoFallthroughIndirect => {
                // We do not include the callee, to allow for convenient intra-function analysis.
                vec![]
            }
            Op::Return => {
                // XXX: Is it reasonable to set this to empty?
                vec![]
            }
            Op::BranchIndOffset => ins
                .indirect_targets
                .iter()
                .filter_map(|tgt| {
                    if let Some(addr) = input_to_addr(tgt) {
                        Some(addr)
                    } else {
                        debug!(
                            "Branch to unknown machine address. Ignoring for successor.";
                            "ins" => ?ins, "ilpc" => il_addr,
                        );
                        None
                    }
                })
                .collect(),
            Op::Cbranch => {
                let mut v = fallthrough;
                if let Some(addr) = input_to_addr(&ins.inputs[0]) {
                    v.push(addr);
                }
                v
            }
            Op::Copy
            | Op::BoolAnd
            | Op::BoolOr
            | Op::BoolXor
            | Op::BoolNegate
            | Op::FloatAdd
            | Op::FloatSub
            | Op::FloatMult
            | Op::FloatDiv
            | Op::FloatRound
            | Op::FloatNeg
            | Op::FloatAbs
            | Op::FloatSqrt
            | Op::FloatIsNan
            | Op::FloatEqual
            | Op::FloatNotEqual
            | Op::FloatLess
            | Op::FloatLessEqual
            | Op::Float2Float
            | Op::Float2IntTrunc
            | Op::Int2Float
            | Op::IntAdd
            | Op::IntSub
            | Op::IntMult
            | Op::IntUDiv
            | Op::IntURem
            | Op::IntSDiv
            | Op::IntSRem
            | Op::IntEqual
            | Op::IntNotEqual
            | Op::IntCarry
            | Op::IntSBorrow
            | Op::IntSCarry
            | Op::IntSLess
            | Op::IntLess
            | Op::IntAnd
            | Op::IntOr
            | Op::IntXor
            | Op::IntOnesComp
            | Op::IntTwosComp
            | Op::IntZext
            | Op::IntSext
            | Op::IntLeftShift
            | Op::IntURightShift
            | Op::IntSRightShift
            | Op::Popcount
            | Op::Piece
            | Op::SubPiece
            | Op::Load { .. }
            | Op::Store { .. }
            | Op::ScalarLowerOp(_, _)
            | Op::ScalarUpperOp(_, _)
            | Op::PackedVectorOp(_, _)
            | Op::UnderspecifiedOutputModification
            | Op::UnderspecifiedNoOutput
            | Op::Nop => fallthrough,
            Op::FunctionStart => {
                vec![input_to_addr(&ins.inputs[0]).unwrap()]
            }
            Op::ProcessorException | Op::FunctionEnd => vec![],
        }
    }
}

impl Program {
    /// Add aux data for stack pointer fixups
    pub fn add_aux_data_for_stack_pointer_fixups(
        &mut self,
        sp: Variable,
        machine_addr_target: u64,
    ) {
        assert!(CONFIG.stack_pointer_patch_after_call_fallthrough);
        if let Some((orig_sp, mut targets)) =
            std::mem::take(&mut self.aux_data_for_stack_pointer_fixups)
        {
            assert_eq!(sp, orig_sp);
            targets.insert(machine_addr_target);
            self.aux_data_for_stack_pointer_fixups = Some((sp, targets));
        } else {
            self.aux_data_for_stack_pointer_fixups =
                Some((sp, [machine_addr_target].into_iter().collect()));
        }
    }

    /// Add a comment to a machine address
    pub fn add_comment_to_machine_address(&mut self, machine_addr: u64, comment: &str) {
        match self.machine_insn_comments.entry(machine_addr) {
            UnorderedMapEntry::Vacant(v) => {
                v.insert(comment.into());
            }
            UnorderedMapEntry::Occupied(mut o) => {
                *o.get_mut() += "; ";
                *o.get_mut() += comment;
            }
        }
    }
}

impl Program {
    /// Generate the basic structural types from the program
    pub fn infer_structural_types(self: &Rc<Self>) -> StructuralTypes {
        let ssa = Rc::new(SSA::compute_from(self));

        let mut types = StructuralTypes::new(&ssa);

        let mut debug_log_file_name_old = String::new();

        // Merge the phi nodes all together, since they must have the same type
        for (v, vs) in ssa.phi_nodes_iter() {
            for from_v in vs {
                types.capability_phi_node(v.into(), from_v.into());
            }
        }

        // Merge the variables part of the same congruence set from global-value-numbering, since
        // they must have the same type
        let global_value_numbering = GlobalValueNumbering::analyze_from(&ssa);
        for gvn_set in global_value_numbering.congruent_sets_iter() {
            types.capability_gvn_congruent(gvn_set);
        }

        for (il_addr, ins) in self.instructions.iter().enumerate() {
            if CONFIG.dump_inference_log_dot_files {
                use std::io::Write;
                if il_addr == 0 || ins.address != self.instructions[il_addr - 1].address {
                    let debug_log_file_name = format!("inference-log-{:05}.dot", il_addr);
                    write!(
                        std::fs::File::create(&debug_log_file_name).unwrap(),
                        "{}",
                        types.generate_dot(Some(il_addr))
                    )
                    .unwrap();
                    // The lines in the immediately following scope are a _terrible_ hack to produce
                    // visual diffs by highlighting impacted nodes, but it works
                    {
                        if il_addr != 0 {
                            let affected = String::from_utf8(
                                std::process::Command::new("/usr/bin/diff")
                                    .args([
                                        "--unified=0",
                                        &debug_log_file_name_old,
                                        &debug_log_file_name,
                                    ])
                                    .output()
                                    .unwrap()
                                    .stdout,
                            )
                            .unwrap()
                            .lines()
                            .filter(|l| !l.starts_with("+++"))
                            .filter(|l| {
                                l.starts_with('+')
                                    && !l.contains("DebugProgram")
                                    && !l.contains("->")
                            })
                            .map(|l| {
                                l.split_once('+')
                                    .unwrap()
                                    .1
                                    .trim()
                                    .split_once('[')
                                    .unwrap()
                                    .0
                                    .to_string()
                            })
                            .collect::<Vec<_>>();
                            let dot = std::fs::read_to_string(&debug_log_file_name).unwrap();
                            let mut file =
                                std::fs::File::create(format!("inference-log-{:05}.dot", il_addr))
                                    .unwrap();
                            for line in dot.lines() {
                                if line == "}" {
                                    for x in &affected {
                                        writeln!(
                                            file,
                                            r#"{}[style="filled" fillcolor="deepskyblue"]"#,
                                            x
                                        )
                                        .unwrap();
                                    }
                                }
                                writeln!(file, "{}", line).unwrap();
                            }
                            debug_log_file_name_old = debug_log_file_name;
                        }
                    }
                }
            }

            let ins_inp_size = |i: usize| -> Option<usize> { ins.inputs[i].try_size() };
            let ins_out_size = || -> usize { ins.output.try_size().unwrap() };

            match ins.op {
                Op::Nop => {
                    // Do nothing, fallthrough
                }
                Op::ProcessorException => {
                    // Do nothing ("no fallthrough" is taken care of elsewhere)
                }
                Op::UnderspecifiedOutputModification => {
                    // Add no constraints and just fallthrough. The
                    // SSA takes care to disconnect the output from
                    // everything else.
                }
                Op::UnderspecifiedNoOutput => {
                    // Add no constraints and just fallthrough.
                    // TODO: constraints about sizes?
                }
                Op::FunctionStart | Op::FunctionEnd => {
                    // No constraint generation for the sentinels
                }
                Op::Branch
                | Op::CallWithFallthrough
                | Op::CallWithNoFallthrough
                | Op::CallWithFallthroughIndirect
                | Op::CallWithNoFallthroughIndirect => {
                    // No direct type constraints from these operations
                }
                Op::BranchIndOffset | Op::Return => {
                    types.capability_pointer_to_code(ssa.get_input_variable(il_addr, 0));
                }
                Op::Cbranch => {
                    match &ins.inputs[1] {
                        Variable::Unused
                        | Variable::DerefVarnode { .. }
                        | Variable::ILAddress { .. }
                        | Variable::ILOffset { .. }
                        | Variable::MachineAddress { .. }
                        | Variable::StackVariable { .. } => unreachable!(),
                        Variable::Constant { value: _, size: _ } => {
                            // XXX: Is it useful to do something here?
                            // We can _definitely_ figure out the
                            // direction of the branch at this point,
                            // right?
                        }
                        v @ Variable::Varnode { .. } => {
                            types.capability_compared_against_zero(
                                ssa.get_input_variable(il_addr, 1),
                                v.try_size().unwrap(),
                            );
                        }
                    }
                }
                Op::Copy => match &ins.inputs[0] {
                    Variable::Unused
                    | Variable::DerefVarnode { .. }
                    | Variable::ILAddress { .. }
                    | Variable::ILOffset { .. }
                    | Variable::MachineAddress { .. }
                    | Variable::StackVariable { .. } => unreachable!(),
                    Variable::Constant { value: _, size: _ } => {
                        // XXX: Can we say anything else here?
                    }
                    Variable::Varnode { .. } => {
                        let sz = ins_out_size();
                        assert_eq!(ins_inp_size(0).unwrap_or(sz), sz);
                        types.capability_copied_from(
                            ssa.get_output_impacted_variable(il_addr).unwrap(),
                            ssa.get_input_variable(il_addr, 0),
                            sz,
                        );
                    }
                },
                Op::Piece | Op::SubPiece => {
                    // XXX: Can we say anything more than the size info?
                    //
                    // Look at https://github.com/jaybosamiya/type-reconstruction/issues/5 for
                    // related discussion.
                    //
                    // Currently, since we have size sets, it _seems_ reasonable that at least for
                    // SubPiece when input1 is 0 allows us to perform type unification. Need to see
                    // if we can do anything more.
                    if ins.op == Op::SubPiece
                        && matches!(ins.inputs[1], Variable::Constant { value: 0, size: _ })
                    {
                        types.capability_have_same_type(
                            ssa.get_output_impacted_variable(il_addr).unwrap(),
                            ssa.get_input_variable(il_addr, 0),
                        );
                    }
                }
                Op::BoolNegate => {
                    let sz = ins_out_size();
                    assert_eq!(ins_inp_size(0).unwrap_or(sz), sz);
                    let op = BooleanOp::Negate;
                    let v = ssa.get_output_impacted_variable(il_addr).unwrap();
                    types.capability_known_boolean(v.clone());
                    types.capability_boolean_op(v.clone(), op, sz);
                    let a = ssa.get_input_variable(il_addr, 0);
                    types.capability_known_boolean(a.clone());
                    types.capability_boolean_op(a, op, sz);
                }
                Op::BoolAnd | Op::BoolOr | Op::BoolXor => {
                    let op = match ins.op {
                        Op::BoolAnd => BooleanOp::And,
                        Op::BoolOr => BooleanOp::Or,
                        Op::BoolXor => BooleanOp::Xor,
                        _ => unreachable!(),
                    };
                    let sz = ins_out_size();
                    assert_eq!(ins_inp_size(0).unwrap_or(sz), sz);
                    assert_eq!(ins_inp_size(1).unwrap_or(sz), sz);
                    let v = ssa.get_output_impacted_variable(il_addr).unwrap();
                    types.capability_known_boolean(v.clone());
                    types.capability_boolean_op(v.clone(), op, sz);
                    let a = ssa.get_input_variable(il_addr, 0);
                    types.capability_known_boolean(a.clone());
                    types.capability_boolean_op(a, op, sz);
                    let b = ssa.get_input_variable(il_addr, 1);
                    types.capability_known_boolean(b.clone());
                    types.capability_boolean_op(b, op, sz);
                }
                Op::FloatAdd | Op::FloatSub | Op::FloatMult | Op::FloatDiv => {
                    let op = match ins.op {
                        Op::FloatAdd => FloatOp::Add,
                        Op::FloatSub => FloatOp::Sub,
                        Op::FloatMult => FloatOp::Mult,
                        Op::FloatDiv => FloatOp::Div,
                        _ => unreachable!(),
                    };
                    let sz = ins_out_size();
                    assert_eq!(ins_inp_size(0).unwrap_or(sz), sz);
                    assert_eq!(ins_inp_size(1).unwrap_or(sz), sz);
                    types.capability_float_op(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                        op,
                        sz,
                    );
                    types.capability_float_op(ssa.get_input_variable(il_addr, 0), op, sz);
                    types.capability_float_op(ssa.get_input_variable(il_addr, 1), op, sz);
                }
                Op::ScalarLowerOp(n, vsop) | Op::PackedVectorOp(n, vsop) => {
                    // XXX/TODO: Handle non-lowest points in packed
                    // vector operations (this will require the same
                    // sort of behavior as `Op::ScalarUpperOp` but
                    // repeated over the whole vector. Currently, we
                    // apply the conservative approach of applying the
                    // scalar op on the 0th offset (so we get some
                    // value out of the op) but other offsets are
                    // essentially havoc'd (and thus do not break
                    // conservativeness).
                    match vsop {
                        VectorScalarOp::FloatAdd
                        | VectorScalarOp::FloatSub
                        | VectorScalarOp::FloatMul
                        | VectorScalarOp::FloatDiv => {
                            let op = match vsop {
                                VectorScalarOp::FloatAdd => FloatOp::Add,
                                VectorScalarOp::FloatSub => FloatOp::Sub,
                                VectorScalarOp::FloatMul => FloatOp::Mult,
                                VectorScalarOp::FloatDiv => FloatOp::Div,
                                _ => unreachable!("{vsop:?}"),
                            };
                            let sz: usize = n.into();
                            let vsz = ins_out_size();
                            assert!(sz < vsz);
                            assert_eq!(ins_inp_size(0).unwrap_or(vsz), vsz);
                            assert_eq!(ins_inp_size(1).unwrap_or(vsz), vsz);
                            types.capability_float_op(
                                ssa.get_output_impacted_variable(il_addr).unwrap(),
                                op,
                                sz,
                            );
                            types.capability_float_op(ssa.get_input_variable(il_addr, 0), op, sz);
                            types.capability_float_op(ssa.get_input_variable(il_addr, 1), op, sz);
                        }
                        VectorScalarOp::LogicalShiftLeft => {
                            let sz: usize = n.into();
                            let vsz = ins_out_size();
                            assert!(sz < vsz);
                            assert_eq!(ins_inp_size(0).unwrap_or(vsz), vsz);
                            let op = IntegerOp::LeftShift;
                            types.capability_integer_op(
                                ssa.get_output_impacted_variable(il_addr).unwrap(),
                                op,
                                sz,
                            );
                            types.capability_integer_op(ssa.get_input_variable(il_addr, 0), op, sz);
                            types.capability_integer_op(
                                ssa.get_input_variable(il_addr, 1),
                                IntegerOp::ShiftAmount,
                                ins_inp_size(1).unwrap(),
                            );
                        }
                    }
                }
                Op::ScalarUpperOp(_n, _vsop) => {
                    // XXX/TODO: Handle such operations; this will
                    // require offsetting the point of the operation
                    // within the SSA variable, which we don't yet
                    // support as a direct capability within
                    // `types`. We _could_ layer it via the
                    // colocation, but this would complicate things,
                    // and it should probably be handled differently,
                    // as a special case.
                    //
                    // Currently, by doing nothing, we essentially
                    // havoc the output, which is safe since it is
                    // conservative.
                    //
                    // Note: once the implementation for this op is
                    // done, `Op::PackedVectorOp` would need an update
                    // based on the offsetting (except there we would
                    // loop across a collection of offsets).
                }
                Op::Float2IntTrunc => {
                    let v = ssa.get_output_impacted_variable(il_addr).unwrap();
                    types.capability_integer_op(
                        v,
                        IntegerOp::ConvertFromFloatTrunc,
                        ins_out_size(),
                    );
                    let a = ssa.get_input_variable(il_addr, 0);
                    types.capability_float_op(
                        a,
                        FloatOp::ConvertToIntTrunc,
                        ins_inp_size(0).unwrap(),
                    );
                }
                Op::Int2Float => {
                    let v = ssa.get_output_impacted_variable(il_addr).unwrap();
                    types.capability_float_op(v, FloatOp::ConvertFromInt, ins_out_size());
                    let a = ssa.get_input_variable(il_addr, 0);
                    types.capability_integer_op(
                        a,
                        IntegerOp::ConvertToFloat,
                        ins_inp_size(0).unwrap(),
                    );
                }
                Op::FloatIsNan => {
                    let sz = ins_inp_size(0).unwrap();
                    types.capability_known_boolean(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                    );
                    types.capability_float_op(ssa.get_input_variable(il_addr, 0), FloatOp::Eq, sz);
                }
                Op::FloatEqual | Op::FloatNotEqual | Op::FloatLess | Op::FloatLessEqual => {
                    let op = match ins.op {
                        Op::FloatEqual => FloatOp::Eq,
                        Op::FloatNotEqual => FloatOp::Neq,
                        Op::FloatLess => FloatOp::Lt,
                        Op::FloatLessEqual => FloatOp::LEq,
                        _ => unreachable!(),
                    };
                    let sz = ins_inp_size(0).or(ins_inp_size(1)).unwrap();
                    assert_eq!(ins_inp_size(1).unwrap_or(sz), sz);

                    types.capability_known_boolean(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                    );
                    let a = ssa.get_input_variable(il_addr, 0);
                    let b = ssa.get_input_variable(il_addr, 1);
                    if CONFIG.unify_types_on_comparison_ops {
                        types.capability_have_same_type(a.clone(), b.clone());
                    }
                    types.capability_float_op(a, op, sz);
                    types.capability_float_op(b, op, sz);
                }
                Op::IntAdd
                | Op::IntSub
                | Op::IntMult
                | Op::IntUDiv
                | Op::IntURem
                | Op::IntSDiv
                | Op::IntSRem
                | Op::IntAnd
                | Op::IntOr
                | Op::IntXor => {
                    let op = match ins.op {
                        Op::IntAdd => IntegerOp::Add,
                        Op::IntSub => IntegerOp::Sub,
                        Op::IntMult => IntegerOp::Mult,
                        Op::IntUDiv => IntegerOp::UDiv,
                        Op::IntURem => IntegerOp::URem,
                        Op::IntSDiv => IntegerOp::SDiv,
                        Op::IntSRem => IntegerOp::SRem,
                        Op::IntAnd => IntegerOp::And,
                        Op::IntOr => IntegerOp::Or,
                        Op::IntXor => IntegerOp::Xor,
                        _ => unreachable!(),
                    };
                    let sz = ins_out_size();
                    assert_eq!(ins_inp_size(0).unwrap_or(sz), sz);
                    assert_eq!(ins_inp_size(1).unwrap_or(sz), sz);
                    types.capability_integer_op(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                        op,
                        sz,
                    );
                    types.capability_integer_op(ssa.get_input_variable(il_addr, 0), op, sz);
                    types.capability_integer_op(ssa.get_input_variable(il_addr, 1), op, sz);
                }
                Op::IntLeftShift | Op::IntURightShift | Op::IntSRightShift => {
                    let op = match ins.op {
                        Op::IntLeftShift => IntegerOp::LeftShift,
                        Op::IntURightShift => IntegerOp::URightShift,
                        Op::IntSRightShift => IntegerOp::SRightShift,
                        _ => unreachable!(),
                    };
                    types.capability_integer_op(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                        op,
                        ins_out_size(),
                    );
                    types.capability_integer_op(
                        ssa.get_input_variable(il_addr, 0),
                        op,
                        ins_inp_size(0).unwrap(),
                    );
                    types.capability_integer_op(
                        ssa.get_input_variable(il_addr, 1),
                        IntegerOp::ShiftAmount,
                        ins_out_size(),
                    );
                }
                Op::IntEqual | Op::IntNotEqual | Op::IntLess | Op::IntSLess => {
                    let op = match ins.op {
                        Op::IntEqual => IntegerOp::Eq,
                        Op::IntNotEqual => IntegerOp::Neq,
                        Op::IntLess => IntegerOp::ULt,
                        Op::IntSLess => IntegerOp::SLt,
                        _ => unreachable!(),
                    };
                    let sz = ins_inp_size(0).or(ins_inp_size(1)).unwrap();
                    assert_eq!(ins_inp_size(1).unwrap_or(sz), sz);

                    types.capability_known_boolean(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                    );
                    let a = ssa.get_input_variable(il_addr, 0);
                    let b = ssa.get_input_variable(il_addr, 1);
                    if CONFIG.unify_types_on_comparison_ops {
                        types.capability_have_same_type(a.clone(), b.clone());
                    }
                    types.capability_integer_op(a, op, sz);
                    types.capability_integer_op(b, op, sz);
                }
                Op::IntCarry | Op::IntSCarry | Op::IntSBorrow => {
                    let op = match ins.op {
                        Op::IntCarry => IntegerOp::UCarry,
                        Op::IntSCarry => IntegerOp::SCarry,
                        Op::IntSBorrow => IntegerOp::SBorrow,
                        _ => unreachable!(),
                    };
                    let sz = ins_inp_size(0).or(ins_inp_size(1)).unwrap();
                    assert_eq!(ins_inp_size(0).unwrap_or(sz), sz);
                    assert_eq!(ins_inp_size(1).unwrap_or(sz), sz);

                    types.capability_known_boolean(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                    );
                    let a = ssa.get_input_variable(il_addr, 0);
                    let b = ssa.get_input_variable(il_addr, 1);
                    if CONFIG.unify_types_on_carry_or_borrow_ops {
                        types.capability_have_same_type(a.clone(), b.clone());
                    }
                    types.capability_integer_op(a, op, sz);
                    types.capability_integer_op(b, op, sz);
                }
                Op::IntOnesComp | Op::IntTwosComp => {
                    let op = match ins.op {
                        Op::IntOnesComp => IntegerOp::OnesComplement,
                        Op::IntTwosComp => IntegerOp::TwosComplement,
                        _ => unreachable!(),
                    };
                    let sz = ins_out_size();
                    assert_eq!(ins_inp_size(0).unwrap_or(sz), sz);
                    types.capability_integer_op(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                        op,
                        sz,
                    );
                    types.capability_integer_op(ssa.get_input_variable(il_addr, 0), op, sz);
                }
                Op::FloatRound | Op::FloatNeg | Op::FloatAbs | Op::FloatSqrt => {
                    let op = match ins.op {
                        Op::FloatRound => FloatOp::Round,
                        Op::FloatNeg => FloatOp::Neg,
                        Op::FloatAbs => FloatOp::Abs,
                        Op::FloatSqrt => FloatOp::Sqrt,
                        _ => unreachable!(),
                    };
                    let sz = ins_out_size();
                    assert_eq!(ins_inp_size(0).unwrap_or(sz), sz);
                    types.capability_float_op(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                        op,
                        sz,
                    );
                    types.capability_float_op(ssa.get_input_variable(il_addr, 0), op, sz);
                }
                Op::Float2Float => {
                    let (op_src, op_tgt) = (
                        FloatOp::ConvertToDifferentSizedFloat,
                        FloatOp::ConvertFromDifferentSizedFloat,
                    );
                    let tgt_sz = ins_out_size();
                    let src_sz = ins_inp_size(0).unwrap();
                    types.capability_float_op(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                        op_tgt,
                        tgt_sz,
                    );
                    types.capability_float_op(ssa.get_input_variable(il_addr, 0), op_src, src_sz);
                }
                Op::IntZext | Op::IntSext => {
                    let (op_src, op_tgt) = match ins.op {
                        Op::IntZext => (IntegerOp::ZeroExtendSrc, IntegerOp::ZeroExtendTgt),
                        Op::IntSext => (IntegerOp::SignExtendSrc, IntegerOp::SignExtendTgt),
                        _ => unreachable!(),
                    };
                    let tgt_sz = ins_out_size();
                    let src_sz = ins_inp_size(0).unwrap();
                    assert!(src_sz < tgt_sz);
                    types.capability_integer_op(
                        ssa.get_output_impacted_variable(il_addr).unwrap(),
                        op_tgt,
                        tgt_sz,
                    );
                    types.capability_integer_op(ssa.get_input_variable(il_addr, 0), op_src, src_sz);
                }
                Op::Popcount => {
                    // XXX: Should we do anything with the result?
                    types.capability_integer_op(
                        ssa.get_input_variable(il_addr, 0),
                        IntegerOp::Popcount,
                        ins_inp_size(0).unwrap(),
                    );
                }
                Op::Load => {
                    let src = &ins.inputs[0];
                    match src {
                        Variable::Unused
                        | Variable::Constant { .. }
                        | Variable::ILAddress { .. }
                        | Variable::ILOffset { .. }
                        | Variable::MachineAddress { .. }
                        | Variable::Varnode { .. }
                        | Variable::StackVariable { .. } => unreachable!(),
                        Variable::DerefVarnode {
                            derefval_address_space_idx: _,
                            derefval_size,
                            addr_address_space_idx,
                            addr_offset: _,
                        } => {
                            assert_eq!(ins.output.try_size().unwrap(), *derefval_size);
                            assert_eq!(
                                self.address_spaces[*addr_address_space_idx].wordsize,
                                self.pointer_size
                            );
                            let to_loc = ssa.get_output_impacted_variable(il_addr).unwrap();
                            types.capability_deref(
                                ssa.get_input_variable(il_addr, 0),
                                self.pointer_size,
                                to_loc,
                                *derefval_size,
                            );
                        }
                    }
                }
                Op::Store => {
                    let store_value = &ins.inputs[1];
                    let dst = &ins.inputs[0];
                    match dst {
                        Variable::Unused
                        | Variable::Constant { .. }
                        | Variable::ILAddress { .. }
                        | Variable::ILOffset { .. }
                        | Variable::MachineAddress { .. }
                        | Variable::StackVariable { .. } => unreachable!(),
                        Variable::Varnode { .. } => unreachable!(),
                        Variable::DerefVarnode {
                            derefval_address_space_idx: _,
                            derefval_size,
                            addr_address_space_idx,
                            addr_offset: _,
                        } => {
                            if let Some(s) = store_value.try_size() {
                                assert_eq!(*derefval_size, s, "{:?}", ins);
                            }

                            assert_eq!(
                                self.address_spaces[*addr_address_space_idx].wordsize,
                                self.pointer_size
                            );
                            types.capability_deref(
                                ssa.get_input_variable(il_addr, 0),
                                self.pointer_size,
                                ssa.get_input_variable(il_addr, 1),
                                *derefval_size,
                            );
                        }
                    }
                }
            }
        }
        types.propagate_pointerness_through_arithmetic_constraints();
        types.canonicalize_indexes();
        types
    }

    /// Get the function index for an arbitrary IL PC
    pub fn function_index_for_il_ip(&self, il_pc: usize) -> usize {
        self.functions
            .iter()
            .position(|(_fnm, _unaff, bbs, _entry)| {
                bbs.iter().any(|&bb| self.basic_blocks[bb].contains(&il_pc))
            })
            .expect("should only be called on PCs that exist in some function")
    }

    /// Get the `FunctionStart` IL PC for an arbitrary IL PC. Also see [`function_index_for_il_ip`].
    pub(crate) fn function_start_il_ip_for_il_ip(&self, il_pc: usize) -> usize {
        let fn_idx = self.function_index_for_il_ip(il_pc);
        let (_fnm, _unaff, _bbs, entry) = &self.functions[fn_idx];
        let func_start_il_pc = entry.1;
        assert_eq!(self.instructions[func_start_il_pc].op, Op::FunctionStart);
        func_start_il_pc
    }

    /// Get the unaffected variables for a call to `target`
    pub fn get_unaffected_variables_for_call_to(
        &self,
        target: Variable,
        caller_il_pc: usize,
    ) -> UnorderedSet<Variable> {
        let Variable::MachineAddress { addr } = target else {
            panic!("Call to non-machine address found: {:?}", target)
        };

        let mut result: UnorderedSet<Variable> = Default::default();
        let mut found_function = false;

        for (_fnm, unaff, _bbs, entry) in &self.functions {
            if entry.0 == addr {
                result.extend(unaff.iter().cloned());
                found_function = true;
                break;
            }
        }

        if let Some((sp, sp_fixups)) = &self.aux_data_for_stack_pointer_fixups {
            if sp_fixups.contains(&addr) {
                result.insert(sp.clone());
            }
        }

        if CONFIG.calling_convention_match_caller_if_unknown_for_callee && !found_function {
            let (fnm, unaff, _bbs, _entry) =
                &self.functions[self.function_index_for_il_ip(caller_il_pc)];
            result.extend(unaff.iter().cloned());
            trace!(
                "Matching unknown calling convention to caller's";
                "target" => ?target,
                "caller_il_pc" => caller_il_pc,
                "func" => fnm,
            );
        }

        if !found_function && result.is_empty() {
            debug!("Call to unknown function address, clobbering everything"; "addr" => addr);
        }

        result
    }
}

/// A representation of the external IL variable
#[derive(PartialEq, Eq, Hash, Debug, Clone, PartialOrd, Ord)]
pub struct ExternalVariable(pub String);
impl std::fmt::Display for ExternalVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A mapping between our internal IL variables and the variables for which types are expected to be
/// reconstructed.
#[derive(Debug)]
pub struct ILVariableMap {
    /// A map from external variables to an internal IL function and set of internal IL variables
    /// within that function
    pub varmap: UnorderedMap<ExternalVariable, (usize, Vec<Variable>)>,
    /// The stack pointer used in this program
    pub stack_pointer: (String, Variable),
}
