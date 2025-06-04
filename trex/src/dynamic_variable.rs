//! Define dynamically-scoped variables.

/// This macro defines convenient dynamically-scoped variables to provide runtime conditional
/// behavior for situations where the behavior cannot be controlled as nicely using an
/// argument. This is common in situations like [`std::fmt::Debug`] where since the trait signature
/// is fixed, one cannot pass additional arguments, but a type might want to define different debug
/// "views".
macro_rules! dynamic_variable {
    ($varname:ident, $with_var_set:ident, $if_var_set:ident) => {
        thread_local! {
            static $varname: std::cell::Cell<bool> = std::cell::Cell::new(false);
        }
        #[allow(non_snake_case)]
        pub fn $with_var_set<T>(f: impl FnOnce() -> T) -> T {
            $varname.with(|var_x| {
                let old_x = var_x.replace(true);
                let res = f();
                var_x.replace(old_x);
                res
            })
        }
        #[allow(non_snake_case)]
        fn $if_var_set<T>(then_f: impl FnOnce() -> T, else_f: impl FnOnce() -> T) -> T {
            $varname.with(|var_x| if var_x.get() { then_f() } else { else_f() })
        }
    };
}

pub(crate) use dynamic_variable;
