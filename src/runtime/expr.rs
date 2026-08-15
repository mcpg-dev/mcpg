//! Re-export of [`mcpg_expr`].
//!
//! The CEL-backed dynamic-value engine lived here historically. It
//! moved to its own workspace crate (`libs/expr/`) so the HTTP
//! backend plugin could compile and evaluate operator-supplied
//! `${arguments.X}` / `${context.X}` / `${env.X}` expressions
//! in-process. The gateway re-exports the surface so existing call
//! sites need no churn.

pub(crate) use mcpg_expr::{
    DynamicValue, ExprContext, ExprRequestContext, resolve_env_in_string, validate_header_value,
};

#[allow(unused_imports)]
pub(crate) use mcpg_expr::{cel_value_to_json, json_to_cel, validate_header_name};
