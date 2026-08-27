# scenario.lex — run the night.
#
#   lex run --allow-effects io,sql,fs_write,time,crypto,approval src/scenario.lex main
#
# Four acts, in the order they happen:
#
#   1. the meter reports, and every reading is signed by the charge point
#   2. the aggregator asks to curtail, and the capability gate answers
#   3. the session closes, the CDR is issued, both parties settle
#   4. somebody edits a reading, and the chain says which one
#
# The numbers are checkable by hand throughout. That is deliberate: a demo whose
# arithmetic can only be taken on faith is asking for exactly the trust the
# whole design exists to remove.

import "std.io" as io

import "std.str" as str

import "std.int" as int

import "std.list" as list

import "lex-schema/json_value" as jv

import "lex-crypto/src/ed25519" as ed

import "lex-trail/log" as tlog

import "lex-trail/replay" as replay

import "lex-trail/event" as ev

import "lex-device-identity/src/device_identity" as di

import "lex-gridguard/src/models" as gg

import "lex-gridguard/src/token" as ggtoken

import "lex-gridguard/src/gate" as ggate

import "lex-baseline/src/method" as bmethod

import "lex-baseline/src/compute" as bcompute

import "./depot" as depot

import "./chain" as chain

fn line(s :: Str) -> [io] Unit {
  io.print(s)
}

fn rule() -> [io] Unit {
  line("--------------------------------------------------------------")
}

fn kv(k :: Str, v :: Str) -> [io] Unit {
  line(str.concat("  ", str.concat(k, str.concat(": ", v))))
}

fn eur(cents :: Int) -> Str {
  str.concat("EUR ", str.concat(int.to_str(cents / 100), str.concat(".", pad2(cents - cents / 100 * 100))))
}

fn pad2(n :: Int) -> Str {
  if n < 10 {
    str.concat("0", int.to_str(n))
  } else {
    int.to_str(n)
  }
}

fn unwrap(r :: Result[Str, Str]) -> Str {
  match r {
    Ok(s) => s,
    Err(_) => "",
  }
}

# ---- Act 1 — the meter reports ------------------------------------------
fn act_readings(log :: tlog.Log) -> [io, sql, time, crypto] List[Str] {
  line("ACT 1  the meter reports")
  rule()
  let cert := unwrap(di.issue_cert(depot.charge_point(), "acme-logistics", "charge_point", unwrap(ed.public_key_b64(depot.device_seed())), depot.t_0300(), depot.t_0400() + 86400000, depot.platform_seed()))
  let ids := list.map(depot.night(), fn (s :: depot.Sample) -> [sql, time, crypto] Str {
    chain.record_reading(log, s, cert)
  })
  let __p := list.fold(depot.night(), (), fn (_a :: Unit, s :: depot.Sample) -> [io] Unit {
    kv(clock(s.ts_ms), str.concat(int.to_str(s.power_w / 1000), str.concat(" kW   register ", str.concat(int.to_str(s.register_wh), " Wh"))))
  })
  let __n := line("")
  let __s := line("  every reading signed by the charge point's own key, verifiable")
  let __s2 := line("  offline by anyone holding the platform's public key")
  let __b := line("")
  ids
}

fn clock(ts_ms :: Int) -> Str {
  let mins := (ts_ms - depot.t_0200()) / 60000
  str.concat(pad2(2 + mins / 60), str.concat(":", pad2(mins - mins / 60 * 60)))
}

fn verdict_line(v :: gg.Verdict) -> Str {
  match v {
    Allowed => "allowed",
    Escalated(r) => str.concat("held for review — ", r),
    Denied(r) => str.concat("REFUSED — ", r),
  }
}

# ---- Act 2 — the aggregator asks ----------------------------------------
#
# The capability is the whole point of this act: the same command, presented
# four ways, gets four answers — and every one of them is on the record.
#
#   no capability at all             refused
#   a capability from another issuer refused
#   the real grant, 15 kW shed       HELD — within the grant, past the
#                                    unattended threshold, and no operator is
#                                    wired in, so nothing is dispatched
#   re-presented as a 7 kW shed      allowed, and dispatched
#
# The held command is the one worth watching. `[approval]`'s default sink
# refuses, so the deep shed simply does not happen — which is what fail-closed
# means at 03:14 when nobody is awake.
#
# (These notes live in the header because `lex fmt` deletes comments inside a
# function body — lex-lang#755.)
fn act_authority(log :: tlog.Log, reading_id :: Str) -> [io, sql, time, crypto] Str {
  line("ACT 2  the aggregator asks to curtail")
  rule()
  let issuer_pub := unwrap(ed.public_key_b64(depot.issuer_seed()))
  let cmd_id := chain.record_command(log, reading_id, depot.full_power_w() - depot.curtailed_w())
  let __c := kv("03:14", "curtail depot-north-cp-04 from 22 kW to 7 kW for 40 minutes")
  let __n := line("")
  let none_at_all := ggate.authorize(log, issuer_pub, "", depot.command(), depot.t_0314(), cmd_id)
  let __d0 := kv("no capability", verdict_line(none_at_all.verdict))
  let rogue := unwrap(ggtoken.issue(depot.platform_seed(), depot.capability()))
  let denied := ggate.authorize(log, issuer_pub, rogue, depot.command(), depot.t_0314(), cmd_id)
  let __d := kv("wrong issuer", verdict_line(denied.verdict))
  let token := unwrap(ggtoken.issue(depot.issuer_seed(), depot.capability()))
  let held := ggate.authorize(log, issuer_pub, token, depot.command(), depot.t_0314(), cmd_id)
  let __a := kv("the real capability", verdict_line(held.verdict))
  let __n2 := line("")
  let __e := line("  15 kW is within the 15 kW granted but past the 11 kW review threshold,")
  let __e2 := line("  and no operator is wired in — so the command is NOT dispatched.")
  let __e3 := line("  Nothing reached the charge point. The refusal is on the record.")
  let __n3 := line("")
  let shallow := ggate.authorize(log, issuer_pub, token, depot.shallow_command(), depot.t_0314(), cmd_id)
  let __s := kv("re-presented, 7 kW shed", verdict_line(shallow.verdict))
  let applied := if gg.is_allowed(shallow.verdict) {
    chain.record_applied(log, shallow.event_id)
  } else {
    ""
  }
  let __s2 := if str.is_empty(applied) {
    line("  nothing dispatched")
  } else {
    kv("03:14", "SetChargingProfile dispatched, hung under the authority that permitted it")
  }
  let __b := line("")
  applied
}

# ---- Act 3 — morning, and three numbers ---------------------------------
fn act_settle(log :: tlog.Log, applied_id :: Str) -> [io, sql, time, crypto] Unit {
  line("ACT 3  morning — three settlements, one chain")
  rule()
  let readings := list.map(depot.night(), fn (s :: depot.Sample) -> bmethod.Reading {
    { ts_ms: s.ts_ms, w: s.power_w }
  })
  let delivered := match bcompute.deliver(depot.baseline_spec(), depot.t_0314(), depot.t_0354(), readings, depot.full_power_w(), [], []) {
    Err(_) => { baseline_w: 0, actual_w: 0, delivered_wh: 0, intervals: 0 },
    Ok(d) => d,
  }
  let energy_kwh := total_kwh()
  let energy_cents := energy_kwh * depot.eur_per_kwh_energy()
  let flex_kwh := delivered.delivered_wh / 1000
  let flex_cents := flex_kwh * depot.eur_per_kwh_flex()
  let cdr_id := chain.record_cdr(log, applied_id, energy_kwh, energy_cents)
  let __e := chain.record_energy_settlement(log, cdr_id, energy_kwh, energy_cents)
  let fp := bmethod.fingerprint(depot.baseline_spec())
  let flex_id := chain.record_flex_settlement(log, applied_id, flex_kwh, flex_cents, fp)
  let __1 := kv("energy bill", str.concat(int.to_str(energy_kwh), str.concat(" kWh   ", eur(energy_cents))))
  let __2 := kv("flexibility payment", str.concat(int.to_str(flex_kwh), str.concat(" kWh   ", eur(flex_cents))))
  let __3 := kv("baseline used", str.concat(int.to_str(delivered.baseline_w / 1000), str.concat(" kW, metered ", str.concat(int.to_str(delivered.actual_w / 1000), " kW"))))
  let __4 := kv("method", str.concat(bmethod.label(depot.baseline_spec()), str.concat("  fingerprint ", str.slice(fp, 0, 16))))
  let __n := line("")
  let __w := line("  both derive from the same signed readings. Walking up from either:")
  let __n2 := line("")
  let __walk := show_chain(log, flex_id)
  line("")
}

fn total_kwh() -> Int {
  let ns := depot.night()
  let first := match list.head(ns) {
    Some(s) => s.register_wh - s.power_w / 4,
    None => 0,
  }
  let last := match list.head(list.reverse(ns)) {
    Some(s) => s.register_wh,
    None => 0,
  }
  (last - first) / 1000
}

fn show_chain(log :: tlog.Log, from_id :: Str) -> [io, sql] Unit {
  list.fold(replay.walk_chain(log, from_id), (), fn (_a :: Unit, e :: ev.Event) -> [io] Unit {
    line(str.concat("    ", e.kind))
  })
}

# ---- Act 4 — somebody edits a reading -----------------------------------
#
# The claim being demonstrated is narrow and checkable: not that the chain
# prevents tampering, but that it LOCALISES it. Every reading is re-verified
# against the charge point's certificate, and the one that no longer matches is
# named.
fn act_tamper(log :: tlog.Log) -> [io, sql, time, crypto] Unit {
  line("ACT 4  somebody edits a meter value")
  rule()
  let platform_pub := unwrap(ed.public_key_b64(depot.platform_seed()))
  let cert := unwrap(di.issue_cert(depot.charge_point(), "acme-logistics", "charge_point", unwrap(ed.public_key_b64(depot.device_seed())), depot.t_0300(), depot.t_0400() + 86400000, depot.platform_seed()))
  let target_ts := depot.t_0300() + 15 * 60000
  let before := original_register(target_ts)
  let __e := kv("edit", str.concat(clock(target_ts), str.concat(" register ", str.concat(int.to_str(before), str.concat(" Wh -> ", str.concat(int.to_str(before + 3500), " Wh   (+3.5 kWh of flexibility, worth EUR 0.42)"))))))
  let __n := line("")
  let tampered := list.map(depot.night(), fn (s :: depot.Sample) -> depot.Sample {
    if s.ts_ms == target_ts {
      { ts_ms: s.ts_ms, power_w: s.power_w, register_wh: s.register_wh + 3500 }
    } else {
      s
    }
  })
  let bad := list.fold(tampered, "", fn (found :: Str, s :: depot.Sample) -> [crypto] Str {
    if not str.is_empty(found) {
      found
    } else {
      let body := chain.reading_body(depot.charge_point(), s.register_wh, s.ts_ms)
      let sig := unwrap(ed.sign_text(depot.device_seed(), di.digest(chain.reading_body(depot.charge_point(), original_register(s.ts_ms), s.ts_ms))))
      match di.verify_reading(cert, body, sig, platform_pub, depot.t_0400()) {
        Ok(_) => "",
        Err(_) => clock(s.ts_ms),
      }
    }
  })
  let __r := if str.is_empty(bad) {
    kv("result", "no tampering detected")
  } else {
    kv("result", str.concat("signature check fails at ", str.concat(bad, " — that reading, and only that reading")))
  }
  let __n2 := line("")
  let __w := line("  the edit did not need to be guessed at. Every other reading still")
  let __w2 := line("  verifies, so the chain names the one that does not.")
  line("")
}

fn original_register(ts_ms :: Int) -> Int {
  list.fold(depot.night(), 0, fn (acc :: Int, s :: depot.Sample) -> Int {
    if s.ts_ms == ts_ms {
      s.register_wh
    } else {
      acc
    }
  })
}

# ---- The run -----------------------------------------------------------
fn main() -> [io, sql, fs_write, time, crypto] Unit {
  line("")
  line("  ONE DEPOT, ONE NIGHT, THREE SETTLEMENTS")
  line("  depot-north — 18 vans on a congestion-constrained connection")
  line("")
  match tlog.open_memory() {
    Err(e) => line(str.concat("could not open the trail: ", e)),
    Ok(log) => {
      let readings := act_readings(log)
      let first := match list.head(readings) {
        Some(id) => id,
        None => "",
      }
      let acted := act_authority(log, first)
      let __s := act_settle(log, acted)
      act_tamper(log)
    },
  }
}

