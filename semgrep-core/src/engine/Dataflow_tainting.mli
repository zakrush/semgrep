(** A match that spans multiple functions (aka "deep").
  * E.g. Call('foo(a)', PM('sink(x)')) is an indirect match for 'sink(x)'
  * through the function call 'foo(a)'. *)
type deep_match =
  | PM of Pattern_match.t  (** A direct match.  *)
  | Call of AST_generic.expr * deep_match
      (** An indirect match through a function call. *)

type source = deep_match

type sink = deep_match

type taint = Src of source | Arg of (* position *) int

module Tainted : Set.S with type elt = taint

type finding = Sink of Tainted.elt * sink | Return of Tainted.elt

type mapping = Tainted.t Dataflow_core.mapping
(** Map for each node/var whether a variable is "tainted" *)

type fun_env = (Dataflow_core.var, Pattern_match.Set.t) Hashtbl.t
(** Set of "tainted" functions in the overall program.
  * Note that here [Dataflow.var] is a string of the form "<source name>:<sid>". *)

type config = {
  filepath : Common.filename;  (** Deep Semgrep *)
  rule_id : string;  (** Deep Semgrep *)
  is_source : AST_generic.any -> Pattern_match.t list;
  is_sink : AST_generic.any -> Pattern_match.t list;
  is_sanitizer : AST_generic.any -> Pattern_match.t list;
  found_tainted_sink :
    Dataflow_core.var option ->
    finding list ->
    Tainted.t Dataflow_core.env ->
    unit;
}
(** This can use semgrep patterns under the hood. Note that a source can be an
  * instruction but also an expression. *)

val pm_of_deep : deep_match -> Pattern_match.t

val unify_meta_envs :
  ('a * Metavariable.mvalue) list ->
  ('a * Metavariable.mvalue) list ->
  ('a * Metavariable.mvalue) list option

val hook_tainted_function :
  (config -> AST_generic.expr -> finding list) option ref

val fixpoint :
  config ->
  fun_env ->
  Dataflow_core.var option ->
  ?in_env:Tainted.t Dataflow_core.VarMap.t ->
  IL.cfg ->
  mapping
(** Main entry point, [fixpoint config fun_env opt_name cfg] returns a mapping
  * (effectively a set) containing all the tainted variables in [cfg]. Besides,
  * if it finds an instruction that consumes tainted data, then it will invoke
  * [config.found_tainted_sink] which can perform any side-effectful action.
  *
  * Parameter [fun_env] is a set of tainted functions in the overall program;
  * it provides basic interprocedural capabilities.
  *
  * Parameter [opt_name] is the name of the function being analyzed, if it has
  * a name. When [Some name] is given, and there is a tainted return statement in
  * [cfg], the function [name] itself will be added to [fun_env] by side-effect.
*)
