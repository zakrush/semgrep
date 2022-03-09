type var = Dataflow_core.var
(** A string of the form "<source name>:<sid>". *)

(** A match that spans multiple functions (aka "deep").
  * E.g. Call('foo(a)', PM('sink(x)')) is an indirect match for 'sink(x)'
  * through the function call 'foo(a)'. *)
type deep_match =
  | PM of Pattern_match.t  (** A direct match.  *)
  | Call of AST_generic.expr * deep_match
      (** An indirect match through a function call. *)

type source = deep_match

type sink = deep_match

type taint =
  | Src of source  (** An actual taint source (`pattern-sources:` match). *)
  | Arg of (* position *) int
      (** A taint variable (potential taint coming through an argument). *)

(** Function-level finding (not necessarily a Semgrep finding). These may
  * depend on taint variables so they must be interpreted on a specific
  * context. *)
type finding =
  | Sink of taint * sink  (** Taint may go into a sink inside the function. *)
  | Return of taint  (** Function's output may be tainted. *)

module Tainted : Set.S with type elt = taint
(** A set of taint sources. *)

type config = {
  filepath : Common.filename;  (** File under analysis, for Deep Semgrep. *)
  rule_id : string;  (** Taint rule id, for Deep Semgrep. *)
  is_source : AST_generic.any -> Pattern_match.t list;
      (** Test whether 'any' is a taint source, this corresponds to
      * 'pattern-sources:' in taint-mode. *)
  is_sink : AST_generic.any -> Pattern_match.t list;
      (** Test whether 'any' is a sink, this corresponds to 'pattern-sinks:'
      * in taint-mode. *)
  is_sanitizer : AST_generic.any -> Pattern_match.t list;
      (** Test whether 'any' is a sanitizer, this corresponds to
      * 'pattern-sanitizers:' in taint-mode. *)
  found_tainted_sink :
    var option (** function name ('None' if anonymous) *) ->
    finding list ->
    Tainted.t Dataflow_core.env ->
    unit;
      (** Callback to report findings. *)
}
(** Taint rule instantiated for a given file.
  *
  * For a source to taint a sink, the bindings of both source and sink must be
  * unifiable. Same applies for a sanitizer to remove taint from a source.
  * See 'unify_meta_envs'. *)

type mapping = Tainted.t Dataflow_core.mapping
(** Mapping from variables to taint sources (if the variable is tainted).
  * If a variable is not in the map, then it's not tainted. *)

type fun_env = (var, Pattern_match.Set.t) Hashtbl.t
(** Set of functions known to act as taint sources (their output is
  * tainted). This is used for a HACK to do some poor-man's intrafile
  * interprocedural taint tracking. TO BE DEPRECATED. *)

val pm_of_deep : deep_match -> Pattern_match.t

val unify_meta_envs :
  Metavariable.bindings -> Metavariable.bindings -> Metavariable.bindings option

val hook_tainted_function :
  (config -> AST_generic.expr -> finding list) option ref
(** Deep Semgrep *)

val fixpoint :
  config ->
  fun_env ->
  var option ->
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
