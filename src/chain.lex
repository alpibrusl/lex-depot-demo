# chain.lex — the night, written onto one trail.
#
# Every event kind here is the one the production services write:
# `meter.reading` and `curtail.applied` and `cdr.issued` come from lex-csms,
# `curtail.command` from lex-ems, and `grid.intent` / `grid.allowed` /
# `grid.denied` from lex-gridguard's gate. The demo replays that vocabulary on
# a single in-memory trail so the whole night is visible in one place.
#
# What is NOT re-implemented: the capability check, the signature verification
# and the volume computation are all the real packages. Only the plumbing that
# would otherwise be four HTTP services is collapsed here.
#
# The shape being demonstrated:
#
#   settlement.energy → cdr.issued ──┐
#                                    ├─→ curtail.applied → grid.allowed
#   settlement.flex  ────────────────┘        → grid.intent
#                                             → curtail.command
#                                             → meter.reading

import "std.str" as str

import "std.int" as int

import "std.list" as list

import "lex-schema/json_value" as jv

import "lex-trail/log" as tlog

import "lex-crypto/src/ed25519" as ed

import "lex-device-identity/src/device_identity" as di

import "./depot" as depot

fn kind_meter_reading() -> Str {
  "meter.reading"
}

fn kind_curtail_command() -> Str {
  "curtail.command"
}

fn kind_curtail_applied() -> Str {
  "curtail.applied"
}

fn kind_cdr_issued() -> Str {
  "cdr.issued"
}

fn kind_settlement_energy() -> Str {
  "settlement.energy"
}

fn kind_settlement_flex() -> Str {
  "settlement.flex"
}

fn append(log :: tlog.Log, kind :: Str, parent :: Str, payload :: Str) -> [sql, time] Str {
  let p := if str.is_empty(parent) {
    None
  } else {
    Some(parent)
  }
  match tlog.append(log, kind, p, payload) {
    Err(_) => "",
    Ok(e) => e.id,
  }
}

# ---- Readings ----------------------------------------------------------
#
# The canonical body the charge point signs. Same discipline as the production
# path: fixed field order, so the device and any verifier produce identical
# bytes.
fn reading_body(cp_id :: Str, register_wh :: Int, ts_ms :: Int) -> Str {
  jv.stringify(JObj([("cp_id", JStr(cp_id)), ("register_wh", JInt(register_wh)), ("ts_ms", JInt(ts_ms))]))
}

# A reading as it lands on the trail: the values, and the evidence that the
# meter — not this program — produced them.
fn reading_payload(s :: depot.Sample, sig :: Str) -> Str {
  jv.stringify(JObj([("cp_id", JStr(depot.charge_point())), ("power_w", JInt(s.power_w)), ("register_wh", JInt(s.register_wh)), ("ts_ms", JInt(s.ts_ms)), ("signature", JStr(sig)), ("signed", JBool(true))]))
}

fn record_reading(log :: tlog.Log, s :: depot.Sample, cert :: Str) -> [sql, time, crypto] Str {
  let body := reading_body(depot.charge_point(), s.register_wh, s.ts_ms)
  let sig := match ed_sign(body) {
    Ok(v) => v,
    Err(_) => "",
  }
  append(log, kind_meter_reading(), "", reading_payload(s, sig))
}

fn ed_sign(body :: Str) -> [crypto] Result[Str, Str] {
  ed.sign_text(depot.device_seed(), di.digest(body))
}

# ---- The decision, the authority, the dispatch -------------------------
fn record_command(log :: tlog.Log, parent :: Str, shed_w :: Int) -> [sql, time] Str {
  append(log, kind_curtail_command(), parent, jv.stringify(JObj([("site_id", JStr(depot.depot())), ("agent_id", JStr(depot.aggregator())), ("shed_w", JInt(shed_w)), ("window_start_ms", JInt(depot.t_0314())), ("window_end_ms", JInt(depot.t_0354())), ("driver", JStr("oscp"))])))
}

fn record_applied(log :: tlog.Log, parent :: Str) -> [sql, time] Str {
  append(log, kind_curtail_applied(), parent, jv.stringify(JObj([("cp_id", JStr(depot.charge_point())), ("target_w", JInt(depot.curtailed_w()))])))
}

fn record_cdr(log :: tlog.Log, parent :: Str, kwh :: Int, eur_cents :: Int) -> [sql, time] Str {
  append(log, kind_cdr_issued(), parent, jv.stringify(JObj([("cp_id", JStr(depot.charge_point())), ("kwh", JInt(kwh)), ("eur_cents", JInt(eur_cents))])))
}

# ---- Both settlements --------------------------------------------------
fn record_energy_settlement(log :: tlog.Log, parent :: Str, kwh :: Int, eur_cents :: Int) -> [sql, time] Str {
  append(log, kind_settlement_energy(), parent, jv.stringify(JObj([("payer", JStr(depot.depot())), ("kwh", JInt(kwh)), ("eur_cents", JInt(eur_cents))])))
}

fn record_flex_settlement(log :: tlog.Log, parent :: Str, kwh :: Int, eur_cents :: Int, fingerprint :: Str) -> [sql, time] Str {
  append(log, kind_settlement_flex(), parent, jv.stringify(JObj([("payer", JStr(depot.aggregator())), ("kwh", JInt(kwh)), ("eur_cents", JInt(eur_cents)), ("method_fingerprint", JStr(fingerprint))])))
}

