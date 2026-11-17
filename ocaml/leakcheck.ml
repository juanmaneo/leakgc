(* ============================================================
   leakcheck.ml — a runtime "leak detector + mark-and-sweep GC"

   Simulates what Valgrind reports at process exit, but runs the
   collection *during* execution, inspired by OCaml's major GC
   (tri-color mark-and-sweep pacing).

   Build/run:  ocaml leakcheck.ml
     or compile native:  ocamlopt leakcheck.ml -o leakcheck
   (stdlib only — no unix / ocamlfind needed)

   Model:
   - Every allocation registers a Block { id, size, site, refs }
   - Roots are declared explicitly (globals, stacks...)
   - A collection: mark from roots, sweep unmarked -> "leaked"
   - Pacing: collect every N allocations (like minor GC frequency)

   Structural note: mark/sweep/collect are defined *before* alloc,
   because alloc triggers collections. (An earlier draft used a
   failwith "stub" forward declaration; that could never work —
   top-level let bindings capture the binding visible at their
   definition point, so a later redefinition of collect would not
   rebind alloc's reference. Nothing in mark/sweep/collect calls
   alloc, so plain reordering suffices; no let rec needed.)
   ============================================================ *)

(* ---------- The simulated heap ---------- *)

type block = {
  id        : int;
  size      : int;              (* bytes "allocated" *)
  site      : string;           (* allocation call-site (Valgrind-style) *)
  mutable refs : int list;      (* ids of blocks this one points to *)
  mutable marked : bool;
  mutable freed  : bool;
}

module H = Hashtbl

let heap : (int, block) H.t = H.create 1024
let roots : int list ref = ref []
let next_id = ref 0
let bytes_allocated = ref 0
let collect_every = 64                (* pace: collection threshold *)
let allocs_since_gc = ref 0
let collections = ref 0
let verbose = ref true

let log fmt =
  if !verbose then Printf.printf fmt else Printf.ifprintf stdout fmt

(* ---------- Mark phase (tri-color, worklist style) ---------- *)

let rec mark_from worklist =
  match worklist with
  | [] -> ()
  | id :: rest ->
    (match H.find_opt heap id with
     | None | Some { freed = true; _ } -> mark_from rest
     | Some b ->
       if b.marked then mark_from rest             (* already black *)
       else begin
         b.marked <- true;                         (* gray -> black *)
         mark_from (b.refs @ rest)
       end)

let mark () =
  List.iter (fun r ->
      match H.find_opt heap r with
      | Some b when not b.freed ->
        if not b.marked then begin
          b.marked <- true;
          mark_from b.refs                         (* seed worklist *)
        end
      | _ -> ())
    !roots

(* ---------- Sweep phase: find & report the "lost" ---------- *)

type leak_report = {
  total_lost_blocks : int;
  total_lost_bytes  : int;
  by_site           : (string * int * int) list;  (* site, blocks, bytes *)
  retained_bytes    : int;
}

let sweep ~free_leaks =
  (* gather lost blocks first; mutate the table only after iteration,
     since modifying a Hashtbl during H.iter is unspecified *)
  let lost = ref [] in
  H.iter (fun _ b ->
      if not b.freed && not b.marked then lost := b :: !lost) heap;
  if free_leaks then
    List.iter (fun b -> b.freed <- true; H.remove heap b.id) !lost;
  (* reset marks for next cycle *)
  H.iter (fun _ b -> b.marked <- false) heap;
  let grouped =
    List.fold_left (fun acc b ->
        let n, sz = try List.assoc b.site acc with Not_found -> (0, 0) in
        (b.site, (n + 1, sz + b.size)) :: List.remove_assoc b.site acc)
      [] !lost
    |> List.map (fun (site, (n, sz)) -> (site, n, sz))
    |> List.sort (fun (_, _, s1) (_, _, s2) -> compare s2 s1)
  in
  { total_lost_blocks = List.length !lost;
    total_lost_bytes  = List.fold_left (fun a b -> a + b.size) 0 !lost;
    by_site = grouped;
    (* live bytes, computed from the actual table contents — immune to
       the cumulative-counter drift the handover warned about *)
    retained_bytes = H.fold (fun _ b acc -> acc + b.size) heap 0 }

(* ---------- Reporting (Valgrind-style) ---------- *)

let print_report r =
  log "\n== LEAKCHECK SUMMARY ==\n";
  if r.total_lost_blocks = 0 then
    log "   no leaks are possible: all blocks reachable from roots\n"
  else begin
    log "   definitely lost: %d blocks in %d bytes\n"
      r.total_lost_blocks r.total_lost_bytes;
    List.iter (fun (site, n, sz) ->
        log "     at %s: %d block(s), %d bytes\n" site n sz)
      r.by_site
  end;
  log "   retained (live) heap: %d bytes\n" r.retained_bytes;
  log "== END SUMMARY ==\n%!"

(* ---------- Public: run a collection ---------- *)

let collect ?(free_leaks = true) ?(report = !verbose) () =
  incr collections;
  mark ();
  let r = sweep ~free_leaks in
  if report then print_report r;
  r

(* ---------- Allocation API ---------- *)

(* allocate size bytes at given call-site, returns block id *)
let alloc ?(refs=[]) ~site size =
  incr allocs_since_gc;
  (* Runtime pacing: trigger collection like OCaml's major slice trigger.
     Must run BEFORE the new block is registered — the block isn't rooted
     yet, so a collection after registration would sweep the very block
     being returned (the caller hasn't had a chance to root it). *)
  if !allocs_since_gc >= collect_every then begin
    allocs_since_gc := 0;
    ignore (collect ~free_leaks:true ~report:!verbose ())
  end;
  incr next_id;
  let b = { id = !next_id; size; site;
            (* filter refs after the trigger: a pacing collection may have
               freed some of the pointees *)
            refs = List.filter (fun r -> H.mem heap r) refs;
            marked = false; freed = false } in
  H.replace heap b.id b;
  bytes_allocated := !bytes_allocated + size;
  b.id

let add_root id = roots := id :: !roots
let remove_root id = roots := List.filter ((<>) id) !roots

(* object graph: make a point to b (retains b) *)
let connect a b =
  match H.find_opt heap a, H.find_opt heap b with
  | Some xa, Some _ ->
    if not (List.mem b xa.refs) then xa.refs <- b :: xa.refs
  | _ -> ()

(* drop an edge: may orphan the target *)
let disconnect a b =
  match H.find_opt heap a with
  | Some xa -> xa.refs <- List.filter ((<>) b) xa.refs
  | None -> ()

(* ============================================================
   DEMO — three classic leak scenarios:
   1. clean code: everything freed/reachable
   2. cyclic garbage: unreachable ring (marks catch it!)
   3. the "old Windows game" pattern: alloc and forget
   ============================================================ *)

let demo () =
  log "--- scenario 1: well-behaved code ---\n";
  let root = alloc ~site:"main.scenario1:12" 512 in
  add_root root;
  let child = alloc ~site:"load_texture:88" 4096 in
  connect root child;
  ignore (collect ());

  log "\n--- scenario 2: cyclic garbage (unreachable ring) ---\n";
  (* build a 3-node cycle, keep no root -> mark-and-sweep's raison d'être *)
  let a = alloc ~site:"build_node:41" 64 in
  let b = alloc ~site:"build_node:41" 64 in
  let c = alloc ~site:"build_node:41" 64 in
  connect a b; connect b c; connect c a;
  ignore (collect ());

  log "\n--- scenario 3: the old Windows game pattern ---\n";
  (* alloc at level start, never free, never rooted, game "quits" *)
  for _level = 1 to 4 do
    ignore (alloc ~site:"load_level_textures:210" 65536)
  done;
  ignore (collect ());

  log "\ndone: %d collections, %d bytes total allocated\n%!"
    !collections !bytes_allocated

let () = demo ()
