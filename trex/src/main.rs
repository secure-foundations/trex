use trex::*;

use std::path::PathBuf;

use clap::Parser;

/// Reconstruct types from binaries
#[derive(Parser, Debug)]
#[clap(about, version, author)]
enum Args {
    /// Reconstruct types from Ghidra IL
    FromGhidra {
        /// Path to a exported PCode file, produced by `PCodeExporter.java`
        exported_pcode: PathBuf,
        /// Path to a exported variables file, produced by `VariableExporter.java`
        ///
        /// If this file is not provided, only types for auto-detected input variables is provided;
        /// TRex however computes types for all detected SSA variables. For this firehose of types,
        /// pass `-Z enable-show-all-ssa-variables-if-no-vars-file-provided`.
        exported_vars: Option<PathBuf>,
        /// Path to output file for structural types
        #[clap(long)]
        output_structural: Option<PathBuf>,
        /// Path to output file for C-like types
        #[clap(long)]
        output_c_like: Option<PathBuf>,
        /// Output full inferred structural types result as a GraphViz `.dot` file to the given path
        #[clap(long)]
        debug_output_graphviz: Option<PathBuf>,
        /// Disable terminal logging, even for high severity alerts. Strongly discouraged for normal
        /// use.
        #[clap(long)]
        debug_disable_terminal_logging: bool,
        /// Force blocking for terminal logging. If too many messages are being spewed the logger,
        /// by default, does not block, but instead dumps a dropped-messages alert. This option
        /// forces it to block and dump even if too many are being sent.
        #[clap(long)]
        debug_forced_blocking_terminal_logging: bool,
        /// Path to send log (as JSON) to
        ///
        /// Error or higher severity alerts will still continue being shown at stderr (in addition
        /// to being added to the log)
        #[clap(long = "--log")]
        log_file: Option<PathBuf>,
        /// Debug level (repeat for more: 0-warn, 1-info, 2-debug, 3-trace)
        #[clap(short, long, parse(from_occurrences))]
        debug: usize,
        /// Path to dump debug SSA-lifted program to
        #[clap(long)]
        dump_ssa_lifted: Option<PathBuf>,
        /// Advanced configuration options to tweak the inference behavior
        #[clap(short = 'Z', long, arg_enum)]
        advanced_config: Vec<inference_config::CommandLineInferenceConfig>,
    },
}

fn main() {
    let args = Args::parse();

    match args {
        Args::FromGhidra {
            exported_pcode,
            exported_vars,
            output_structural,
            output_c_like,
            debug_output_graphviz,
            debug_disable_terminal_logging,
            debug_forced_blocking_terminal_logging,
            log_file,
            debug,
            dump_ssa_lifted,
            advanced_config,
        } => {
            let _log_guard = slog_scope::set_global_logger(crate::log::FileAndTermDrain::new(
                debug,
                debug_disable_terminal_logging,
                debug_forced_blocking_terminal_logging,
                log_file,
            ));

            inference_config::InferenceConfig::initialize(advanced_config);

            let prog = ghidra_lifter::lift_from(
                &std::fs::read_to_string(exported_pcode).expect("PCode file could not be read"),
            );
            let vars = exported_vars.map(|exported_vars| {
                ghidra_variable_lifter::lift_from(
                    &std::fs::read_to_string(exported_vars)
                        .expect("Variables file could not be read"),
                    &prog,
                )
            });

            let types = prog.infer_structural_types();

            if let Some(path) = dump_ssa_lifted {
                use std::io::Write;
                write!(
                    std::fs::File::create(path).unwrap(),
                    "{:?}",
                    types.ssa.debug_program(true, None)
                )
                .unwrap();
            }

            let structuredtypes = if inference_config::CONFIG.enable_colocation_analysis {
                let colocated = starts_at_analysis::CoLocated::analyze(&std::rc::Rc::new(types));

                let aggregate =
                    aggregate_types::AggregateTypes::analyze(&std::rc::Rc::new(colocated));

                aggregate.to_structural_types()
            } else {
                types
            };

            if let Some(path) = debug_output_graphviz {
                use std::io::Write;
                write!(
                    std::fs::File::create(path).unwrap(),
                    "{}",
                    structuredtypes.generate_dot(None)
                )
                .unwrap();
            }

            let serializable_types = structuredtypes.serialize(&vars);

            let serializable_types = if inference_config::CONFIG.enable_type_rounding {
                let mut serializable_types = serializable_types;
                type_rounding::round_up_to_c_types(serializable_types.types_mut());
                serializable_types
            } else {
                serializable_types
            };

            if let Some(path) = output_structural {
                use std::io::Write;
                write!(
                    std::fs::File::create(path).unwrap(),
                    "{}",
                    serializable_types.serialize()
                )
                .unwrap();
            } else {
                println!("{}", serializable_types.serialize());
            }

            if let Some(path) = output_c_like {
                use std::io::Write;
                write!(
                    std::fs::File::create(path).unwrap(),
                    "{}",
                    c_type_printer::PrintableCTypes::new(&serializable_types)
                )
                .unwrap();
            } else {
                println!(
                    "{}",
                    c_type_printer::PrintableCTypes::new(&serializable_types)
                );
            }

            log::trace!("Done");
        }
    }
}
