# lex-depot-demo — the scenario's own assertions.
#
# A demo that drifts from what it claims is worse than no demo, because it is
# shown to people who cannot check it in the room. These pin the four things
# the run asserts out loud:
#
#   the deep shed is HELD, not run
#   a shallower one within the unattended limit IS run
#   the two settlements are different quantities off the same readings
#   an edited reading is localised to the reading that was edited
#   the over-claim is the gap between what was invoiced and what was measured
#   the operator's choice of reading to edit is honoured, or refused by name
#
# If any of that stops being true, this goes red before the demo does.

import "std.io" as io

import "std.str" as str

import "std.int" as int

import "std.list" as list

import "lex-crypto/src/ed25519" as ed

import "lex-trail/log" as tlog

import "lex-trail/event" as ev

import "lex-device-identity/src/device_identity" as di

import "lex-gridguard/src/models" as gg

import "lex-gridguard/src/token" as ggtoken

import "lex-gridguard/src/gate" as ggate

import "lex-baseline/src/method" as bmethod

import "lex-baseline/src/compute" as bcompute

import "../src/depot" as depot

import "../src/chain" as chain

import "../src/scenario" as scenario

fn pass() -> Result[Unit, Str] {
  Ok(())
}

fn fail(why :: Str) -> Result[Unit, Str] {
  Err(why)
}

fn assert_true(cond :: Bool, label :: Str) -> Result[Unit, Str] {
  if cond {
    pass()
  } else {
    fail(label)
  }
}

fn unwrap(r :: Result[Str, Str]) -> Str {
  match r {
    Ok(s) => s,
    Err(_) => "",
  }
}

fn issuer_pub() -> [crypto] Str {
  unwrap(ed.public_key_b64(depot.issuer_seed()))
}

fn token() -> [crypto] Str {
  unwrap(ggtoken.issue(depot.issuer_seed(), depot.capability()))
}

fn fresh_log() -> [sql, fs_write] Option[tlog.Log] {
  match tlog.open_memory() {
    Err(_) => None,
    Ok(l) => Some(l),
  }
}

# ---- Act 2's claims ----------------------------------------------------
fn test_the_deep_shed_is_held_not_run() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let d := ggate.authorize(log, issuer_pub(), token(), depot.command(), depot.t_0314(), "")
      match d.verdict {
        Escalated(_) => pass(),
        Allowed => fail("the 15kW shed must NOT run unattended — the demo says it is held"),
        Denied(r) => fail(str.concat("the 15kW shed is within the grant and should be held, not denied: ", r)),
      }
    },
  }
}

fn test_the_shallower_shed_is_allowed() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let d := ggate.authorize(log, issuer_pub(), token(), depot.shallow_command(), depot.t_0314(), "")
      assert_true(gg.is_allowed(d.verdict), "a 7kW shed is inside the unattended limit and runs")
    },
  }
}

fn test_a_command_with_no_capability_is_refused() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let d := ggate.authorize(log, issuer_pub(), "", depot.command(), depot.t_0314(), "")
      assert_true(not gg.is_allowed(d.verdict), "a command carrying no capability is refused")
    },
  }
}

fn test_a_capability_from_another_issuer_is_refused() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let rogue := unwrap(ggtoken.issue(depot.platform_seed(), depot.capability()))
      let d := ggate.authorize(log, issuer_pub(), rogue, depot.command(), depot.t_0314(), "")
      assert_true(not gg.is_allowed(d.verdict), "a capability signed by an untrusted key is refused")
    },
  }
}

# ---- Act 3's claims ----------------------------------------------------
fn night_readings() -> List[bmethod.Reading] {
  list.map(depot.night(), fn (s :: depot.Sample) -> bmethod.Reading {
    { ts_ms: s.ts_ms, w: s.power_w }
  })
}

fn delivered_wh() -> Int {
  match bcompute.deliver(depot.baseline_spec(), depot.t_0314(), depot.t_0354(), night_readings(), depot.full_power_w(), [], []) {
    Err(_) => 0 - 1,
    Ok(d) => d.delivered_wh,
  }
}

# 22 kW held at 15 kW is a 7 kW shed; over the 40-minute window that is
# 7000 * 2 400 000 / 3 600 000 = 4666 Wh. Checkable by hand, which is the point.
fn test_the_flexibility_volume_is_what_the_meter_shows() -> Result[Unit, Str] {
  assert_true(delivered_wh() == 4666, str.concat("a 7kW shed over 40 minutes is 4666Wh, got ", int.to_str(delivered_wh())))
}

# The demo's whole premise is that these are different quantities off one set of
# readings. If they ever coincide the story stops landing, so it is asserted.
fn test_the_energy_bill_and_the_flex_payment_are_different_quantities() -> Result[Unit, Str] {
  let ns := depot.night()
  let first := match list.head(ns) {
    Some(s) => s.register_wh - s.power_w / 4,
    None => 0,
  }
  let last := match list.head(list.reverse(ns)) {
    Some(s) => s.register_wh,
    None => 0,
  }
  let energy_wh := last - first
  assert_true(energy_wh > delivered_wh() * 4, "the energy consumed over the night is a much larger quantity than the flexibility delivered inside one window")
}

fn test_the_method_fingerprint_is_stable() -> [crypto] Result[Unit, Str] {
  assert_true(bmethod.fingerprint(depot.baseline_spec()) == bmethod.fingerprint(depot.baseline_spec()) and not str.is_empty(bmethod.fingerprint(depot.baseline_spec())), "the settled volume travels with a stable method fingerprint")
}

# ---- Act 4's claim -----------------------------------------------------
#
# The claim is localisation, not prevention: the chain names the reading that
# was edited and leaves the others verifying.
fn test_an_edited_reading_is_localised() -> [crypto] Result[Unit, Str] {
  let cert := unwrap(di.issue_cert(depot.charge_point(), "acme-logistics", "charge_point", unwrap(ed.public_key_b64(depot.device_seed())), depot.t_0300(), depot.t_0400() + 86400000, depot.platform_seed()))
  let platform_pub := unwrap(ed.public_key_b64(depot.platform_seed()))
  let target := depot.t_0300() + 15 * 60000
  let broken := list.fold(depot.night(), [], fn (acc :: List[Str], s :: depot.Sample) -> [crypto] List[Str] {
    let shown := if s.ts_ms == target {
      s.register_wh + 3500
    } else {
      s.register_wh
    }
    let sig := unwrap(ed.sign_text(depot.device_seed(), di.digest(chain.reading_body(depot.charge_point(), s.register_wh, s.ts_ms))))
    match di.verify_reading(cert, chain.reading_body(depot.charge_point(), shown, s.ts_ms), sig, platform_pub, depot.t_0400()) {
      Ok(_) => acc,
      Err(_) => list.concat(acc, [int.to_str(s.ts_ms)]),
    }
  })
  assert_true(list.len(broken) == 1, str.concat("exactly one reading should fail verification, got ", int.to_str(list.len(broken))))
}

# ---- Suite -------------------------------------------------------------
#
# `lex test` calls `run_all` and DISCARDS what it returns (lex-lang#757), so a
# returned failure count reports `ok` however many assertions failed. This
# prints each failure by name and then raises.
# The number Act 3 puts next to the invoice. 10 kWh claimed against 4666 Wh
# measured is a 114% over-claim; if that arithmetic drifts, the demo is
# asserting something false to a room that cannot check it.
fn test_the_overclaim_is_the_gap_between_claimed_and_measured() -> Result[Unit, Str] {
  let over := scenario.overclaim_pct(delivered_wh(), 10000)
  assert_true(over == 114, str.concat("10kWh claimed against a measured 4666Wh is a 114% over-claim, got ", int.to_str(over)))
}

# A window that measured nothing must not report an infinite over-claim, and
# must not divide by zero.
fn test_an_unmeasured_window_claims_nothing() -> Result[Unit, Str] {
  assert_true(scenario.overclaim_pct(0, 10000) == 0, "an unmeasured window reports no over-claim rather than dividing by zero")
}

# TAMPER=HH:MM resolves to the sample at that time.
fn test_the_operators_clock_resolves_to_a_reading() -> Result[Unit, Str] {
  match scenario.clock_to_ts("03:45") {
    None => Err("03:45 must parse"),
    Some(ts) => assert_true(ts == depot.t_0200() + 105 * 60000 and scenario.is_sample(ts), "03:45 resolves to a reading that was actually taken"),
  }
}

# Anything that is not a time, and any time that was never sampled, is refused
# rather than silently tampering with nothing.
fn test_a_time_that_was_never_sampled_is_refused() -> Result[Unit, Str] {
  let unsampled := match scenario.clock_to_ts("03:07") {
    None => false,
    Some(ts) => scenario.is_sample(ts),
  }
  let garbage := match scenario.clock_to_ts("banana") {
    None => true,
    Some(_) => false,
  }
  assert_true(not unsampled and garbage, "03:07 was never sampled and \"banana\" is not a clock — both are refused")
}

# The banner and the README count settlements out loud, and once said three
# when the chain wrote two. The count is pinned here rather than left to
# whoever edits the copy next.
#
# `cdr.issued` is deliberately not counted. A charge detail record is the
# invoice document; the settlements are the money movements.
fn test_the_chain_writes_exactly_three_settlements() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match tlog.open_memory() {
    Err(e) => Err(str.concat("open_memory: ", e)),
    Ok(log) => {
      let cdr := chain.record_cdr(log, "", 38, 1064)
      let __e := chain.record_energy_settlement(log, cdr, 38, 1064)
      let flex := chain.record_flex_settlement(log, cdr, 4, 48, "fp")
      let __g := chain.record_grid_settlement(log, flex, 10, 180)
      match tlog.range(log, 0, 9999999999999) {
        Err(e) => Err(str.concat("range: ", e)),
        Ok(events) => {
          let n := list.fold(events, 0, fn (acc :: Int, e :: ev.Event) -> Int {
            if str.starts_with(e.kind, "settlement.") {
              acc + 1
            } else {
              acc
            }
          })
          assert_true(n == 3, str.concat("a settled night writes three settlements — energy, flex and grid; got ", int.to_str(n)))
        },
      }
    },
  }
}

# The DSO settles on the CLAIM and the depot is paid on the METER, so the
# aggregator's margin is the gap between them. If those two figures ever come
# from the same number, the demo has stopped showing the thing it exists to
# show.
fn test_the_intermediary_is_paid_on_the_claim_and_pays_on_the_meter() -> Result[Unit, Str] {
  let claimed_kwh := (depot.full_power_w() - depot.curtailed_w()) * (depot.t_0354() - depot.t_0314()) / 3600000 / 1000
  let measured_kwh := delivered_wh() / 1000
  let grid_cents := claimed_kwh * depot.eur_per_kwh_grid()
  let flex_cents := measured_kwh * depot.eur_per_kwh_flex()
  assert_true(claimed_kwh > measured_kwh and grid_cents > flex_cents and grid_cents - flex_cents == 132, str.concat("the DSO pays on 10kWh claimed and the depot is paid on 4kWh measured, leaving EUR 1.32 on the gap; got ", int.to_str(grid_cents - flex_cents)))
}

fn results() -> [sql, fs_write, time, crypto] List[(Str, Result[Unit, Str])] {
  [("the_deep_shed_is_held_not_run", test_the_deep_shed_is_held_not_run()), ("the_shallower_shed_is_allowed", test_the_shallower_shed_is_allowed()), ("a_command_with_no_capability_is_refused", test_a_command_with_no_capability_is_refused()), ("a_capability_from_another_issuer_is_refused", test_a_capability_from_another_issuer_is_refused()), ("the_flexibility_volume_is_what_the_meter_shows", test_the_flexibility_volume_is_what_the_meter_shows()), ("the_energy_bill_and_the_flex_payment_are_different_quantities", test_the_energy_bill_and_the_flex_payment_are_different_quantities()), ("the_method_fingerprint_is_stable", test_the_method_fingerprint_is_stable()), ("an_edited_reading_is_localised", test_an_edited_reading_is_localised()), ("the_chain_writes_exactly_three_settlements", test_the_chain_writes_exactly_three_settlements()), ("the_intermediary_is_paid_on_the_claim_and_pays_on_the_meter", test_the_intermediary_is_paid_on_the_claim_and_pays_on_the_meter()), ("the_overclaim_is_the_gap_between_claimed_and_measured", test_the_overclaim_is_the_gap_between_claimed_and_measured()), ("an_unmeasured_window_claims_nothing", test_an_unmeasured_window_claims_nothing()), ("the_operators_clock_resolves_to_a_reading", test_the_operators_clock_resolves_to_a_reading()), ("a_time_that_was_never_sampled_is_refused", test_a_time_that_was_never_sampled_is_refused())]
}

fn report(rs :: List[(Str, Result[Unit, Str])]) -> [io] Int {
  list.fold(rs, 0, fn (n :: Int, r :: (Str, Result[Unit, Str])) -> [io] Int {
    match r {
      (name, Ok(_)) => n,
      (name, Err(why)) => {
        let __p := io.print(str.concat("FAIL ", str.concat(name, str.concat(" — ", why))))
        n + 1
      },
    }
  })
}

# The stdlib is total — there is no `panic` — so a division by zero is the
# raise. `zero` arrives as an argument so it survives constant folding.
fn raise_failure(zero :: Int) -> Int {
  1 / zero
}

fn run_all() -> [io, sql, fs_write, time, crypto] Unit {
  let failures := report(results())
  if failures == 0 {
    ()
  } else {
    let __p := io.print(str.concat(int.to_str(failures), " test(s) failed"))
    let __boom := raise_failure(0)
    ()
  }
}

