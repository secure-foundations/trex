#![allow(dead_code)] // temporarily disable dead code lint

pub mod aggregate_types;
pub mod c_type_printer;
pub mod c_types;
pub mod constant_folding;
pub mod containers;
pub mod dataflow;
pub mod dynamic_variable;
pub mod ghidra_lifter;
pub mod ghidra_variable_lifter;
pub mod global_value_numbering;
pub mod il;
pub mod inference_config;
pub mod joinable_container;
pub mod reaching_definitions;
pub mod serialize_structural;
pub mod ssa;
pub mod starts_at_analysis;
pub mod structural;
pub mod tests;
pub mod type_rounding;

pub mod log {
    pub use slog_scope::{crit, debug, error, info, trace, warn};

    pub struct OptionalKV<V: slog::Value>(pub &'static str, pub Option<V>);
    impl<V: slog::Value> slog::KV for OptionalKV<V> {
        fn serialize(
            &self,
            record: &slog::Record,
            serializer: &mut dyn slog::Serializer,
        ) -> slog::Result {
            if let Some(v) = &self.1 {
                v.serialize(record, self.0, serializer)
            } else {
                Ok(())
            }
        }
    }

    pub struct FileAndTermDrain {
        file_drain: Option<slog::Logger>,
        term_drain: slog::Logger,
    }
    impl FileAndTermDrain {
        pub fn new(
            debug_level: usize,
            disable_terminal_logging: bool,
            force_block: bool,
            path: Option<std::path::PathBuf>,
        ) -> slog::Logger {
            use sloggers::Build;

            let debug_level = match debug_level {
                0 => sloggers::types::Severity::Warning,
                1 => sloggers::types::Severity::Info,
                2 => sloggers::types::Severity::Debug,
                3 => sloggers::types::Severity::Trace,
                _ => sloggers::types::Severity::Trace,
            };

            let term_drain = if disable_terminal_logging {
                sloggers::null::NullLoggerBuilder.build().unwrap()
            } else {
                sloggers::terminal::TerminalLoggerBuilder::new()
                    .destination(sloggers::terminal::Destination::Stderr)
                    .level(if path.is_none() {
                        debug_level
                    } else {
                        sloggers::types::Severity::Error
                    })
                    .overflow_strategy(if force_block || path.is_none() {
                        sloggers::types::OverflowStrategy::Block
                    } else {
                        sloggers::types::OverflowStrategy::DropAndReport
                    })
                    .format(sloggers::types::Format::Compact)
                    .build()
                    .unwrap()
            };

            let file_drain = path.map(|path| {
                sloggers::file::FileLoggerBuilder::new(path)
                    .truncate()
                    .level(debug_level)
                    .overflow_strategy(sloggers::types::OverflowStrategy::Block)
                    .format(sloggers::types::Format::Json)
                    .build()
                    .unwrap()
            });

            slog::Logger::root(
                Self {
                    file_drain,
                    term_drain,
                },
                slog::o!(),
            )
        }
    }
    impl slog::Drain for FileAndTermDrain {
        type Ok = ();
        type Err = slog::Never;
        fn log(
            &self,
            r: &slog::Record<'_>,
            kv: &slog::OwnedKVList,
        ) -> Result<<Self as slog::Drain>::Ok, <Self as slog::Drain>::Err> {
            if let Some(f) = &self.file_drain {
                <slog::Logger as slog::Drain>::log(f, r, kv)?;
            }
            <slog::Logger as slog::Drain>::log(&self.term_drain, r, kv)?;
            Ok(())
        }
    }
}
