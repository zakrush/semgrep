val check_rule :
  Rule.t ->
  (string -> Metavariable.bindings -> Parse_info.t list Lazy.t -> unit) ->
  Config_semgrep.t * Equivalence.equivalences ->
  Rule.taint_spec ->
  Xtarget.t ->
  Report.rule_profiling Report.match_result

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

