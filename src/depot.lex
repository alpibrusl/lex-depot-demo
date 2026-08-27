# depot.lex — the 03:14 curtailment, as data.
#
# One depot, one night. Eighteen vans on a connection that cannot carry them
# all; at 03:14 the aggregator curtails four of them from 22 kW to 7 kW for
# forty minutes. By morning three parties settle money against that one event.
#
# Everything here is the scenario's own vocabulary — who, what, when, how much.
# The mechanism lives in the packages this composes; `scenario.lex` runs it.

import "std.str" as str

import "std.int" as int

import "std.list" as list

import "std.bytes" as bytes

import "lex-baseline/src/method" as bmethod

import "lex-gridguard/src/models" as gg

# ---- The clock ---------------------------------------------------------
#
# Fixed instants rather than a real clock, so the demo prints the same story
# every time and a reader can check the arithmetic by hand.
fn t_0200() -> Int {
  1787796000000
}

fn t_0300() -> Int {
  t_0200() + 3600000
}

fn minute() -> Int {
  60000
}

fn t_0314() -> Int {
  t_0300() + 14 * minute()
}

fn t_0354() -> Int {
  t_0300() + 54 * minute()
}

fn t_0400() -> Int {
  t_0300() + 60 * minute()
}

# ---- The parties -------------------------------------------------------
fn depot() -> Str {
  "depot-north"
}

fn charge_point() -> Str {
  "depot-north-cp-04"
}

fn aggregator() -> Str {
  "aggregator-a"
}

fn contract() -> Str {
  "FLEX-2026-11"
}

# The deployment key that issues device certificates, and the charge point's
# own key. Fixed seeds so the run is reproducible; a real deployment holds the
# issuer seed in a control plane and the device seed never leaves the device.
fn platform_seed() -> Bytes {
  bytes.from_str("depot_demo_platform_seed_aaaaaaa")
}

fn device_seed() -> Bytes {
  bytes.from_str("depot_demo_charge_point_bbbbbbbb")
}

fn issuer_seed() -> Bytes {
  bytes.from_str("depot_demo_capability_issuer_ccc")
}

# ---- The night ---------------------------------------------------------
#
# Power in whole watts. Before the window the van draws 22 kW; during it, 7 kW;
# after, back to 22 kW. Quarter-hourly readings, which is what the meter sends.
fn full_power_w() -> Int {
  22000
}

fn curtailed_w() -> Int {
  7000
}

# The energy register is cumulative, so each reading adds the energy drawn since
# the last one. That is what a real meter reports and what a signature covers.
type Sample = { ts_ms :: Int, power_w :: Int, register_wh :: Int }

fn quarter() -> Int {
  15 * minute()
}

# Two hours of quarter-hourly readings, 02:00 to 04:00. The three that fall
# inside 03:14-03:54 carry the curtailed power; the rest are a normal night, and
# they are what makes the energy bill visibly a different quantity from the shed.
fn night() -> List[Sample] {
  list.fold([0, 1, 2, 3, 4, 5, 6, 7], [], fn (acc :: List[Sample], i :: Int) -> List[Sample] {
    let ts := t_0200() + i * quarter()
    let power := if ts >= t_0314() and ts < t_0354() {
      shallow_target_w()
    } else {
      full_power_w()
    }
    let previous := match list.head(list.reverse(acc)) {
      Some(s) => s.register_wh,
      None => 100000,
    }
    list.concat(acc, [{ ts_ms: ts, power_w: power, register_wh: previous + power / 4 }])
  })
}

# ---- What the aggregator was granted -----------------------------------
#
# Shed this charge point by up to 15 kW, never below 3 kW, inside the hour,
# under one contract. No discharge — that is a different act and a separate
# grant. Review above 11 kW.
fn capability() -> gg.Capability {
  { token_id: "cap-2026-11-04", agent_id: aggregator(), assets_allow: [charge_point()], max_shed_w: 15000, min_floor_w: 3000, window_start_ms: t_0300(), window_end_ms: t_0400(), contract: contract(), review_threshold_w: 11000, allow_discharge: false, expires_at_ms: t_0400() + 24 * 3600000, policy_version: 1 }
}

# The command actually issued at 03:14.
fn command() -> gg.Command {
  { asset: charge_point(), target_w: curtailed_w(), baseline_w: full_power_w(), window_start_ms: t_0314(), window_end_ms: t_0354(), contract: contract(), reason: "DSO congestion window" }
}

# The aggregator's answer to having the deep shed held: a shallower one, inside
# the limit it may exercise without waking anybody.
fn shallow_command() -> gg.Command {
  { asset: charge_point(), target_w: 15000, baseline_w: full_power_w(), window_start_ms: t_0314(), window_end_ms: t_0354(), contract: contract(), reason: "DSO congestion window, within unattended limit" }
}

# What the charge point was actually held at, once the deep shed was refused
# for want of an operator and the aggregator re-presented a shallower one.
fn shallow_target_w() -> Int {
  15000
}

# ---- How the delivered volume is measured ------------------------------
#
# The nominated method, because this demo has one night rather than the weeks of
# history a measured method needs — and because it is what the platform settles
# on today. The point being demonstrated is that the method is NAMED and its
# fingerprint travels with the number, not that this particular method is the
# right one for a contract.
fn baseline_spec() -> bmethod.Spec {
  { method: Nominated, interval_ms: quarter(), version: 1 }
}

fn eur_per_kwh_energy() -> Int {
  28
}

fn eur_per_kwh_flex() -> Int {
  12
}

