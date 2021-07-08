(*s: semgrep/tainting/Tainting_generic.ml *)
(*s: pad/r2c copyright *)
(* Yoann Padioleau
 *
 * Copyright (C) 2019-2021 r2c
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation, with the
 * special exception on linking described in file license.txt.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the file
 * license.txt for more details.
 *)
(*e: pad/r2c copyright *)
module AST = AST_generic
module V = Visitor_AST
module R = Rule
module PM = Pattern_match

(*****************************************************************************)
(* Prelude *)
(*****************************************************************************)
(* Simple wrapper around the tainting dataflow-based analysis in pfff.
 *
 * Here we pass matcher functions that uses semgrep patterns to
 * describe the source/sink/sanitizers.
 *)
let _logger = Logging.get_logger [ __MODULE__ ]

(*****************************************************************************)
(* Helpers *)
(*****************************************************************************)

module F2 = IL

module DataflowY = Dataflow.Make (struct
  type node = F2.node

  type edge = F2.edge

  type flow = (node, edge) Ograph_extended.ograph_mutable

  let short_string_of_node n = Display_IL.short_string_of_node_kind n.F2.n
end)

type env = {
  sources : Range.t list;
  sanitizers : Range.t list;
  sinks : Range.t list;
}

let mk_env file ast_and_errors (rule : R.rule) (spec : R.taint_spec) =
  let config = Config_semgrep.default_config (* TODO *) in
  let equivs = [] (* TODO *) in
  let lazy_ast_and_errors = lazy ast_and_errors in
  let file_and_more = (file, rule.languages, lazy_ast_and_errors) in
  let lazy_content = lazy (Common.read_file file) in
  let find_ranges_one pformula =
    let formula = Rule.formula_of_pformula pformula in
    Match_rules.matches_of_formula config equivs rule.id file_and_more
      lazy_content formula None
    |> snd
    |> List.map (fun rwm -> rwm.Range_with_metavars.r)
  in
  let find_ranges pfs = pfs |> List.map find_ranges_one |> List.concat in
  {
    sources = find_ranges spec.sources;
    sanitizers = find_ranges spec.sanitizers;
    sinks = find_ranges spec.sinks;
  }

let any_in_ranges any ranges =
  let tok1, tok2 = Visitor_AST.range_of_any any in
  let r = { Range.start = tok1.charpos; end_ = tok2.charpos } in
  List.exists (Range.( $<=$ ) r) ranges

(*s: function [[Tainting_generic.config_of_rule]] *)
let config_of_rule found_tainted_sink env =
  {
    Dataflow_tainting.is_source = (fun x -> any_in_ranges x env.sources);
    is_sanitizer = (fun x -> any_in_ranges x env.sanitizers);
    is_sink = (fun x -> any_in_ranges x env.sinks);
    found_tainted_sink;
  }

(*e: function [[Tainting_generic.config_of_rule]] *)

(*****************************************************************************)
(* Main entry point *)
(*****************************************************************************)

(*s: function [[Tainting_generic.check2]] *)
let check hook (taint_rules : (Rule.rule * Rule.taint_spec) list) file ast =
  let matches = ref [] in

  let fun_env = Hashtbl.create 8 in

  let check_stmt opt_name def_body =
    let xs = AST_to_IL.stmt def_body in
    let flow = CFG_build.cfg_of_stmts xs in

    taint_rules
    |> List.iter (fun (rule, taint_spec) ->
           let found_tainted_sink x _env =
             let code = x in
             let range_loc = V.range_of_any code in
             let tokens = lazy (V.ii_of_any code) in
             let rule_id =
               {
                 Pattern_match.id = rule.Rule.id;
                 message = rule.Rule.message;
                 pattern_string = "TODO: no pattern_string";
               }
             in
             (* todo: use env from sink matching func?  *)
             Common.push
               { PM.rule_id; file; range_loc; tokens; env = [] }
               matches
           in
           (* TODO: Do this once per rule, not once per function! *)
           let env = mk_env file (ast, []) rule taint_spec in
           let config = config_of_rule found_tainted_sink env in
           let mapping =
             Dataflow_tainting.fixpoint config fun_env opt_name flow
           in
           ignore mapping
           (* TODO
              logger#sdebug (DataflowY.mapping_to_str flow
               (fun () -> "()") mapping);
           *))
  in

  let v =
    V.mk_visitor
      {
        V.default_visitor with
        V.kdef =
          (fun (k, _) ((ent, def_kind) as def) ->
            match def_kind with
            | AST.FuncDef fdef ->
                let opt_name = AST_to_IL.name_of_entity ent in
                check_stmt opt_name fdef.AST.fbody
            | __else__ -> k def);
        V.kfunction_definition =
          (* TODO: Fix double check of function definition *)
          (fun (_k, _) def -> check_stmt None def.AST.fbody);
      }
  in
  (* Check each function definition. *)
  v (AST.Pr ast);
  (* Check the top-level statements.
   * In scripting languages it is not unusual to write code outside
   * function declarations and we want to check this too. We simply
   * treat the program itself as an anonymous function. *)
  check_stmt None (AST.stmt1 ast);

  !matches
  (* same post-processing as for search-mode in Match_rules.ml *)
  |> Common.uniq_by (AST_utils.with_structural_equal PM.equal)
  |> Common.before_return (fun v ->
         v
         |> List.iter (fun (m : Pattern_match.t) ->
                let str = Common.spf "with rule %s" m.rule_id.id in
                hook str m.env m.tokens))
  [@@profiling]

(*e: function [[Tainting_generic.check2]] *)

(*e: semgrep/tainting/Tainting_generic.ml *)
