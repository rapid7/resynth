extern crate concat_with;

#[macro_export]
macro_rules! func_def {
    (@replace $_t:tt $sub:expr) => {
        $sub
    };

    (@len $($tt:tt)*) => {
        {<[()]>::len(&[$(func_def!(@replace $tt ())),*])}
    };

    (
        @pdecl $type:ident
    ) => {
        ArgDecl::Positional(ValType::$type)
    };

    (
        @ndecl $type:expr
    ) => {
        ArgDecl::Named($type)
    };

    (
        @pos $name:ident $type:ident
    ) => {
        ArgDesc {
            name: stringify!($name),
            typ: func_def!(@pdecl $type),
        }
    };

    (
        @named $name:ident $type:expr
    ) => {
        ArgDesc {
            name: stringify!($name),
            typ: func_def!(@ndecl $type),
        }
    };

    (
        $(#[doc = $doc:literal])+
        resynth fn $name:ident
        (
            $($arg_name:ident : $arg_type:ident),* $(,)*
            =>
            $($dfl_name:ident : $dfl_type:expr),* $(,)*
            =>
            $collect_type:ident
        ) -> $return_type:ident
        $exec:expr
    ) => {
        {
            #[allow(unused)]
            use $crate::libapi::{FuncDef, ArgDesc, ArgDecl};
            use $crate::val::ValType;

            #[allow(non_camel_case_types,unused)]
            enum ArgName {
               $($arg_name,)*
               $($dfl_name,)*
            }

            fn arg_pos(name: &str) -> Option<usize> {
                match name {
                    $(stringify!($arg_name) => Some(ArgName::$arg_name as usize),)*
                    $(stringify!($dfl_name) => Some(ArgName::$dfl_name as usize),)*
                    _ => None,
                }
            }

            FuncDef {
                name: stringify!($name),
                return_type: ValType::$return_type,
                args: &[
                    $(func_def!(@pos $arg_name $arg_type),)*
                    $(func_def!(@named $dfl_name $dfl_type),)*
                ],
                arg_pos,
                min_args: func_def!(@len $($arg_name)*),
                collect_type: ValType::$collect_type,
                exec: $exec,
                doc: concat_with::concat_line!($($doc),+),
            }
        }
    };
}

#[macro_export]
macro_rules! module {
    (
        @sym $name:ident $sym:expr
    ) => {
        SymDesc {
            name: stringify!($name),
            sym: $sym,
        }
    };

    (
        $(#[doc = $doc:literal])+
        resynth mod $modname:ident {$(
            $name:ident => $sym:expr,
        )*}
    ) => {
        {
            #[allow(unused)]
            use $crate::libapi::{Module, SymDesc};

            #[allow(non_camel_case_types,unused)]
            enum SymName {
               $($name,)*
            }

            fn lookup(name: &str) -> Option<usize> {
                match name {
                    $(stringify!($name) => Some(SymName::$name as usize),)*
                    _ => None,
                }
            }

            Module {
                name: stringify!($modname),
                symtab: &[
                    $(module!(@sym $name $sym),)*
                ],
                lookup,
                doc: concat_with::concat_line!($($doc),+),
            }
        }
    };
}

#[macro_export]
macro_rules! class {
    (
        @sym $name:ident $sym:expr
    ) => {
        SymDesc {
            name: stringify!($name),
            sym: $sym,
        }
    };

    (
        $(#[doc = $doc:literal])+
        resynth class $modname:ident {$(
            $name:ident => $sym:expr,
        )*}
    ) => {
        {
            #[allow(unused)]
            use $crate::libapi::{ClassDef, SymDesc};

            #[allow(non_camel_case_types,unused)]
            enum MethodName {
               $($name,)*
            }

            fn lookup(name: &str) -> Option<usize> {
                match name {
                    $(stringify!($name) => Some(MethodName::$name as usize),)*
                    _ => None,
                }
            }

            ClassDef {
                name: stringify!($modname),
                symtab: &[
                    $(class!(@sym $name $sym),)*
                ],
                lookup,
                doc: concat_with::concat_line!($($doc),+),
            }
        }
    };
}

#[macro_export]
macro_rules! ok {
    ($st:expr, $fmt:expr $(, $($arg:expr),*)*) => {{
        $st.set_color(ColorSpec::new()
            .set_fg(Some(Color::Green))
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($fmt, $($arg),*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }
}}

#[macro_export]
macro_rules! warn {
    ($st:expr, $fmt:expr $(, $($arg:expr),*)*) => {{
        $st.set_color(ColorSpec::new()
            .set_fg(Some(Color::Yellow))
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($fmt, $($arg),*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }
}}

#[macro_export]
macro_rules! error {
    ($st:expr, $fmt:expr $(, $($arg:expr),*)*) => {{
        $st.set_color(ColorSpec::new()
            .set_fg(Some(Color::Red))
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($fmt, $($arg),*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }
}}

#[macro_export]
macro_rules! notice {
    ($st:expr, $fmt:expr $(, $($arg:expr),*)*) => {{
        $st.set_color(ColorSpec::new()
            .set_bold(true)
            .set_intense(true)
        ).unwrap();
        let ret = print!($fmt, $($arg),*);
        $st.set_color(&ColorSpec::default()).unwrap();
        ret
    }}
}
