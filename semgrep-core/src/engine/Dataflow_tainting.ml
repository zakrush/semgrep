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
open Common
open IL
module G = AST_generic
module F = IL
module D = Dataflow_core
module VarMap = Dataflow_core.VarMap
module PM = Pattern_match

let logger = Logging.get_logger [ __MODULE__ ]

(*****************************************************************************)
(* Prelude *)
(*****************************************************************************)
(* Tainting dataflow analysis.
 *
 * This is a very rudimentary tainting analysis.
 * Very coarse grained (taint whole array/object).
 * This is step1 for taint tracking support in semgrep.
 * This was originally in semgrep-core/src/analyze, but it now depends on Pattern_match,
 * so it was moved to semgrep-core/src/engine
 *)

(*****************************************************************************)
(* Types *)
(*****************************************************************************)

type deep_match = PM of Pattern_match.t | Call of G.expr * deep_match

let rec pm_of_deep = function
  | PM pm -> pm
  | Call (_, dm) -> pm_of_deep dm

type source = deep_match

type sink = deep_match

type taint = Src of source | Arg of (* position *) int

module Tainted = Set.Make (struct
  type t = taint

  let compare_pm pm1 pm2 =
    (* If the pattern matches are obviously different (have different ranges),
     * we are done. If their ranges are the same, we compare their metavariable
     * environments. This is not robust to reordering metavariable environments,
     * e.g.: [("$A",e1);("$B",e2)] is not equal to [("$B",e2);("$A",e1)]. This
     * is potentially a source of duplicate findings.
     *)
    match compare pm1.PM.range_loc pm2.PM.range_loc with
    | 0 -> compare pm1.PM.env pm2.PM.env
    | c -> c

  let rec compare_dm dm1 dm2 =
    match (dm1, dm2) with
    | PM p, PM q -> compare_pm p q
    | PM _, Call _ -> -1
    | Call _, PM _ -> 1
    | Call (c1, d1), Call (c2, d2) ->
        let c_cmp = Int.compare c1.e_id c2.e_id in
        if c_cmp <> 0 then c_cmp else compare_dm d1 d2

  (* TODO: Rely on ppx_deriving.ord ? *)
  let compare t1 t2 =
    match (t1, t2) with
    | Arg i, Arg j -> Int.compare i j
    | Src p, Src q -> compare_dm p q
    | Arg _, Src _ -> -1
    | Src _, Arg _ -> 1
end)

let show_tainted tainted =
  tainted |> Tainted.elements
  |> List.map (function
       | Src _ -> "PM"
       | Arg i -> "Arg " ^ string_of_int i)
  |> String.concat ", "
  |> fun str -> "{ " ^ str ^ " }"

let (env_to_str : ('a -> string) -> 'a VarMap.t -> string) =
 fun val2str env ->
  VarMap.fold (fun dn v s -> s ^ dn ^ ":" ^ val2str v ^ " ") env ""

let _ignore () =
  ignore show_tainted;
  ignore env_to_str

type finding = Sink of Tainted.elt * deep_match | Return of Tainted.elt

(* TODO: s/Return/Propagate, and add Sanitize of Tainted.elt *)

type mapping = Tainted.t Dataflow_core.mapping
(** Map for each node/var of all the pattern matches that originated its taint.
    Anything not included in the map is not tainted. Currently we only strictly need
    the metavariable environment in these pattern matches, but we plan to make use of
    the full pattern match information eventually.
*)

(* HACK: Tracks tainted functions intrafile. *)
type fun_env = (Dataflow_core.var, PM.Set.t) Hashtbl.t

(* is_source/sink/sanitizer returns a list of ways that some piece of code can be matched
 * as a source/sink/sanitizer, what is more important is that the metavariable bindings
 * may differ between them. *)
type config = {
  filepath : Common.filename;
  rule_id : string;
  is_source : G.any -> PM.t list;
  is_sink : G.any -> PM.t list;
  is_sanitizer : G.any -> PM.t list;
  found_tainted_sink :
    Dataflow_core.var option ->
    finding list ->
    Tainted.t Dataflow_core.env ->
    unit;
}
(** This can use semgrep patterns under the hood. Note that a source can be an
  * instruction but also an expression. *)

module DataflowX = Dataflow_core.Make (struct
  type node = F.node

  type edge = F.edge

  type flow = (node, edge) CFG.t

  let short_string_of_node n = Display_IL.short_string_of_node_kind n.F.n
end)

(*****************************************************************************)
(* Hooks *)
(*****************************************************************************)

let hook_tainted_function = ref None

let is_tainted_function_hook config e =
  logger#flash "[taint] is_tainted_function_hook (file=%s, rule=%s): %s\n"
    config.filepath config.rule_id (G.show_expr e);
  match !hook_tainted_function with
  | None -> Tainted.empty
  | Some hook ->
      hook config e
      |> List.filter_map (function
           | Return (Src _ as t) -> Some t
           | _ -> None)
      |> Tainted.of_list

(*****************************************************************************)
(* Helpers *)
(*****************************************************************************)

let str_of_name name = spf "%s:%d" (fst name.ident) name.sid

let orig_is_source config orig = config.is_source (any_of_orig orig)

let orig_is_sanitized config orig = config.is_sanitizer (any_of_orig orig)

let orig_is_sink config orig = config.is_sink (any_of_orig orig)

let set_opt_to_set = function
  | None -> Tainted.empty
  | Some x -> x

(* [unify_meta_envs env1 env1] returns [Some (union env1 env2)] if [env1] and [env2] contain no conflicting metavariable assignments, otherwise [None]. *)
let unify_meta_envs env1 env2 =
  let ( let* ) = Option.bind in
  let xs =
    List.fold_left
      (fun xs (mvar, mval) ->
        let* xs = xs in
        match List.assoc_opt mvar env2 with
        | None -> Some ((mvar, mval) :: xs)
        | Some mval' ->
            if Metavariable.equal_mvalue mval mval' then
              Some ((mvar, mval) :: xs)
            else None)
      (Some []) env1
  in
  let ys =
    List.filter (fun (mvar, _) -> not @@ List.mem_assoc mvar env1) env2
  in
  Option.map (fun xs -> xs @ ys) xs

let set_concat_map f xs =
  xs |> List.map f |> List.fold_left Tainted.union Tainted.empty

let _set_filter_map f pm_set =
  PM.Set.fold
    (fun pm pm_set ->
      match f pm with
      | Some pm' -> PM.Set.add pm' pm_set
      | None -> pm_set)
    pm_set PM.Set.empty

(* @param sink_pm Pattern match of a sink.
   @param src_pms Set of pattern matches corresponding to sources.
   @returns PM.Set.t containing a copy [sink_pm] with an updated metavariable environment for each PM in [src_pms] whose env unifies with [sink_pm]s. *)
let update_meta_envs (sink : sink) (tainted : Tainted.t) : finding list =
  let ( let* ) = Option.bind in
  Tainted.elements tainted
  |> List.filter_map (fun taint ->
         match taint with
         | Arg _ -> Some (Sink (taint, sink))
         | Src src ->
             let src_pm = pm_of_deep src in
             let sink_pm = pm_of_deep sink in
             let* _env = unify_meta_envs sink_pm.PM.env src_pm.PM.env in
             Some (Sink (taint, sink)))

(* @param sink_pms List of sink pattern matches.
   @param src_pms Set of source pattern matches.
   @returns PM.Set.t of all the possible tainted sink pattern matches with their metavariable environments updated
   to include the bindings from the source whose environment unified with it.
 *)
let make_tainted_sink_matches (sinks : sink list) (tainted : Tainted.t) :
    finding list =
  sinks |> List.concat_map (fun sink -> update_meta_envs sink tainted)

(*****************************************************************************)
(* Tainted *)
(*****************************************************************************)

let check_tainted_var config opt_name (fun_env : fun_env)
    (env : Tainted.t VarMap.t) var : Tainted.t =
  (* logger#flash "[taint] check_tainted_var %s" (str_of_name var) ; *)
  let source_pms, sanitize_pms, sink_pms =
    let _, tok = var.ident in
    if Parse_info.is_origintok tok then
      ( config.is_source (G.Tk tok),
        config.is_sanitizer (G.Tk tok),
        config.is_sink (G.Tk tok) )
    else ([], [], [])
  in
  let tainted_pms : Tainted.t =
    Tainted.of_list (List.map (fun pm -> Src (PM pm)) source_pms)
    |> Tainted.union (set_opt_to_set (VarMap.find_opt (str_of_name var) env))
    |> Tainted.union
         (Hashtbl.find_opt fun_env (str_of_name var)
         |> Option.value ~default:PM.Set.empty
         |> PM.Set.elements
         |> List.map (fun pm -> Src (PM pm))
         |> Tainted.of_list)
    (* |> PM.Set.union (is_tainted_function_hook config ((G.Id (var.ident, var.id_info)))) *)
  in
  match sanitize_pms with
  | _ :: _ -> Tainted.empty
  | [] ->
      let found =
        make_tainted_sink_matches
          (sink_pms |> List.map (fun sink -> PM sink))
          tainted_pms
      in
      if found <> [] then config.found_tainted_sink opt_name found env;
      tainted_pms

(* Test whether an expression is tainted, and if it is also a sink,
 * report the finding too (by side effect). *)
let rec check_tainted_expr config opt_name (fun_env : fun_env)
    (env : Tainted.t VarMap.t) exp =
  let check = check_tainted_expr config opt_name fun_env env in
  let sink_pms = orig_is_sink config exp.eorig |> List.map (fun pm -> PM pm) in
  let check_base = function
    | Var var -> check_tainted_var config opt_name fun_env env var
    | VarSpecial _ -> Tainted.empty
    | Mem e -> check e
  in
  let check_offset = function
    | Index e -> check e
    | NoOffset
    | Dot _ ->
        Tainted.empty
  in
  let check_subexpr exp =
    match exp.e with
    | Fetch { base = VarSpecial (This, _); offset = Dot fld; _ } ->
        Hashtbl.find_opt fun_env (str_of_name fld)
        |> Option.value ~default:PM.Set.empty
        |> PM.Set.elements
        |> List.map (fun pm -> Src (PM pm))
        |> Tainted.of_list
    | Fetch
        {
          base =
            Var
              {
                id_info =
                  {
                    G.id_resolved = { contents = Some (G.ImportedEntity _, _) };
                    _;
                  };
                _;
              };
          offset = Dot _;
          _;
        } -> (
        match exp.eorig with
        | SameAs eorig -> is_tainted_function_hook config eorig
        | _ -> Tainted.empty)
    | Fetch { base; offset; _ } ->
        Tainted.union (check_base base) (check_offset offset)
    | FixmeExp (_, _, Some e) -> check e
    | Literal _
    | FixmeExp (_, _, None) ->
        Tainted.empty
    | Composite (_, (_, es, _))
    | Operator (_, es) ->
        set_concat_map check es
    | Record fields -> set_concat_map (fun (_, e) -> check e) fields
    | Cast (_, e) -> check e
  in
  let sanitized_pms = orig_is_sanitized config exp.eorig in
  match sanitized_pms with
  | _ :: _ -> Tainted.empty
  | [] ->
      let tainted_pms =
        Tainted.union (check_subexpr exp)
          (Tainted.of_list
             (orig_is_source config exp.eorig
             |> List.map (fun pm -> Src (PM pm))))
      in
      let found = make_tainted_sink_matches sink_pms tainted_pms in
      if found <> [] then config.found_tainted_sink opt_name found env;
      tainted_pms

(* Test whether an instruction is tainted, and if it is also a sink,
 * report the finding too (by side effect). *)
let check_tainted_instr config opt_name fun_env env instr : Tainted.t =
  let sink_pms =
    orig_is_sink config instr.iorig |> List.map (fun pm -> PM pm)
  in
  let check_expr = check_tainted_expr config opt_name fun_env env in
  let tainted_args = function
    | Assign (_, e) -> check_expr e
    | AssignAnon _ -> Tainted.empty (* TODO *)
    | Call
        ( _,
          {
            e =
              Fetch
                {
                  base =
                    Var
                      {
                        id_info =
                          {
                            G.id_resolved =
                              { contents = Some (G.ImportedEntity _, _) };
                            _;
                          };
                        _;
                      };
                  offset = Dot _;
                  _;
                };
            eorig = SameAs eorig;
            _;
          },
          args ) -> (
        logger#flash "check_tainted_instr Call";
        match !hook_tainted_function with
        | None -> Tainted.empty
        | Some hook ->
            let e_sig = hook config eorig in
            e_sig
            |> List.filter_map (function
                 | Return (Src pm) -> Some (Tainted.singleton (Src pm))
                 | Return (Arg i) ->
                     let arg_i = List.nth args i in
                     Some (check_expr arg_i)
                 | Sink (Arg i, sink) ->
                     let arg_i = List.nth args i in
                     let arg_tainted = check_expr arg_i in
                     arg_tainted
                     |> Tainted.iter (fun t ->
                            config.found_tainted_sink opt_name
                              [ Sink (t, sink) ]
                              env);
                     None
                 | _ -> None)
            |> List.fold_left Tainted.union Tainted.empty)
    | Call (_, e, args) ->
        let e_tainted_pms = check_expr e in
        let args_tainted_pms = set_concat_map check_expr args in
        Tainted.union e_tainted_pms args_tainted_pms
    | CallSpecial (_, _, args) -> set_concat_map check_expr args
    | FixmeInstr _ -> Tainted.empty
  in
  let sanitized_pm_opt = orig_is_sanitized config instr.iorig in
  match sanitized_pm_opt with
  | _ :: _ -> Tainted.empty
  | [] ->
      let tainted_pms =
        Tainted.union (tainted_args instr.i)
          (Tainted.of_list
             (orig_is_source config instr.iorig
             |> List.map (fun pm -> Src (PM pm))))
      in
      let found = make_tainted_sink_matches sink_pms tainted_pms in
      if found <> [] then config.found_tainted_sink opt_name found env;
      tainted_pms

(* Test whether a `return' is tainted, and if it is also a sink,
 * report the finding too (by side effect). *)
let check_tainted_return config opt_name fun_env env tok e =
  let sink_pms =
    config.is_sink (G.Tk tok) @ orig_is_sink config e.eorig
    |> List.map (fun pm -> PM pm)
  in
  let e_tainted_pms = check_tainted_expr config opt_name fun_env env e in
  let found = make_tainted_sink_matches sink_pms e_tainted_pms in
  if found <> [] then config.found_tainted_sink opt_name found env;
  e_tainted_pms

(*****************************************************************************)
(* Transfer *)
(*****************************************************************************)

let union_env = Dataflow_core.varmap_union Tainted.union

let input_env ~enter_env ~(flow : F.cfg) mapping ni =
  let node = flow.graph#nodes#assoc ni in
  match node.F.n with
  | Enter -> enter_env
  | _else -> (
      let pred_envs =
        CFG.predecessors flow ni
        |> Common.map (fun (pi, _) -> mapping.(pi).D.out_env)
      in
      match pred_envs with
      | [] -> VarMap.empty
      | [ penv ] -> penv
      | penv1 :: penvs -> List.fold_left union_env penv1 penvs)

let (transfer :
      config ->
      fun_env ->
      Tainted.t Dataflow_core.env ->
      string option ->
      flow:F.cfg ->
      Tainted.t Dataflow_core.transfn) =
 fun config fun_env enter_env opt_name ~flow
     (* the transfer function to update the mapping at node index ni *)
       mapping ni ->
  (* DataflowX.display_mapping flow mapping show_tainted; *)
  let in' : Tainted.t VarMap.t = input_env ~enter_env ~flow mapping ni in
  (* logger#flash "transfer ni=%d in'=%s" ni (env_to_str show_tainted in'); *)
  let node = flow.graph#nodes#assoc ni in
  let out' : Tainted.t VarMap.t =
    match node.F.n with
    | NInstr x -> (
        let tainted = check_tainted_instr config opt_name fun_env in' x in
        match (Tainted.is_empty tainted, IL.lvar_of_instr_opt x) with
        | true, Some var -> VarMap.remove (str_of_name var) in'
        | false, Some var ->
            VarMap.update (str_of_name var)
              (function
                | None -> Some tainted
                | Some tainted' -> Some (Tainted.union tainted tainted'))
              in'
        | _, None -> in')
    | NReturn (tok, e) -> (
        let tainted = check_tainted_return config opt_name fun_env in' tok e in
        let found =
          tainted |> Tainted.elements |> List.map (fun t -> Return t)
        in
        if found <> [] then config.found_tainted_sink opt_name found in';
        let pmatches =
          tainted |> Tainted.elements
          |> List.filter_map (function
               | Src src -> Some (pm_of_deep src)
               | Arg _ -> None)
          |> PM.Set.of_list
        in
        match opt_name with
        | Some var ->
            (let str = var in
             match Hashtbl.find_opt fun_env str with
             | None ->
                 if not (PM.Set.is_empty pmatches) then
                   Hashtbl.add fun_env str pmatches
             | Some tained' ->
                 Hashtbl.replace fun_env str (PM.Set.union pmatches tained'));
            in'
        | None -> in')
    | _ -> in'
  in
  { D.in_env = in'; out_env = out' }

(*****************************************************************************)
(* Entry point *)
(*****************************************************************************)

let (fixpoint :
      config ->
      fun_env ->
      Dataflow_core.var option ->
      ?in_env:Tainted.t Dataflow_core.VarMap.t ->
      F.cfg ->
      mapping) =
 fun config fun_env opt_name ?in_env flow ->
  let init_mapping =
    DataflowX.new_node_array flow (Dataflow_core.empty_inout ())
  in
  let enter_env =
    match in_env with
    | None -> VarMap.empty
    | Some in_env -> in_env
  in
  (* THINK: Why I cannot just update mapping here ? if I do, the mapping gets overwritten later on! *)
  (* DataflowX.display_mapping flow init_mapping show_tainted; *)
  DataflowX.fixpoint ~eq:Tainted.equal ~init:init_mapping
    ~trans:
      (transfer config fun_env enter_env opt_name ~flow)
      (* tainting is a forward analysis! *)
    ~forward:true ~flow
