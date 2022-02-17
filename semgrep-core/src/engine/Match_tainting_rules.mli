(*
   Check tainting-mode rules.
   Return matches, errors, match time.
*)
val check :
  match_hook:
    (string -> Metavariable.bindings -> Parse_info.t list Lazy.t -> unit) ->
  Config_semgrep.t * Equivalence.equivalences ->
  (Rule.rule * Rule.taint_spec) list ->
  Xtarget.t ->
  Report.times Report.match_result

(* used by testing code *)
val check_bis :
  match_hook:
    (string -> Metavariable.bindings -> Parse_info.t list Lazy.t -> unit) ->
  Config_semgrep.t * Equivalence.equivalences ->
  (Rule.rule * Rule.taint_spec) list ->
  Common.filename ->
  Lang.t ->
  Target.t ->
  Pattern_match.t list


(* Deep Semgrep *)

val check_def : Common.filename ->
  Lang.t ->
  Rule.rule list ->
  (Common.filename * string, Dataflow_tainting.config) Hashtbl.t ->
  string -> AST_generic.function_definition -> unit

val taint_config_of_rule : Config_semgrep_t.t ->
  Equivalence.equivalences ->
  Common.filename ->
  AST_generic.program * Semgrep_error_code.error list ->
  Rule.rule ->
  Rule.taint_spec ->
  (Dataflow_core.var option -> Dataflow_tainting.result list -> Dataflow_tainting.Tainted.t Dataflow_core.env -> unit) -> Dataflow_tainting.config

