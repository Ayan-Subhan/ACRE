import { useEffect, useState } from 'react'

const cache = new Map<string, Promise<unknown>>()

function load<T>(name: string): Promise<T> {
  if (!cache.has(name)) {
    cache.set(name, fetch(`/data/${name}.json`).then((r) => {
      if (!r.ok) throw new Error(`${name}.json: ${r.status}`)
      return r.json()
    }))
  }
  return cache.get(name) as Promise<T>
}

/** Fetch one of the exported JSON files (frontend/public/data). */
export function useData<T>(name: string): T | null {
  const [data, setData] = useState<T | null>(null)
  useEffect(() => {
    let live = true
    load<T>(name).then((d) => live && setData(d)).catch((e) => console.error(e))
    return () => { live = false }
  }, [name])
  return data
}

// ---- types for the exported files -------------------------------------------
export interface Overview {
  milestones: { id: string; name: string; status: 'done' | 'next' | 'planned' }[]
  flow_rates: { benign_fpr_validator: number; attack_reject_validator: number; eids_recall: number; leak_by_spec: Record<string, number> }
  headline: { best_bal_acc: number; validator_fpr: number; best_pass_and_evade: number; best_attacker: string; n_features: number }
}

export interface ValidatorData {
  provenance: { n_rows: number; range_tolerance: number; dependency_percentile: number }
  features: string[]
  range: { feature: string; min: number; max: number }[]
  log1p_columns: string[]
  integrality: string[]
  dependency: { name: string; kind: string; tolerance: number; p999: number }[]
  dependency_pruned: { name: string; reason: string }[]
  distribution: { group: string; threshold: number; train_rows: number; global_profile: boolean }[]
  fpr_budget: number
  clean: { benign_fpr: number; attack_reject: number; benign_n: number; attack_n: number }
  fpr_by_group: { group: string; n: number; fpr: number }[]
  reject_by_category: { category: string; n: number; rejected: number; range: number; integrality: number; dependency: number; distribution: number }[]
  art_sets: { set: string; combined: number; range: number; integrality: number; dependency: number; distribution: number; attributable: number; evade_model_only: number; pass_and_evade: number }[]
  realizable_stop: { spec: string; attack: string; fooled: number; stopped: number }[]
}

export interface IdsData {
  metrics: { model: string; accuracy: number; balanced_accuracy: number; precision: number; recall: number; f1: number; fpr: number; tn: number; fp: number; fn: number; tp: number; params: number; epochs: number; train_s: number; threshold: number }[]
  history: Record<string, { loss: number[]; val_loss: number[]; accuracy: number[]; val_accuracy: number[] }>
  per_category_recall: { category: string; support: number; MLP: number; CNN: number; LSTM: number }[]
  evasion: { model: string; attack: string; clean_acc: number; adv_acc: number; evasion: number; feats_changed: number }[]
  realizable: { spec: string; attack: string; model: string; evasion: number; pass_and_evade: number; evades_all3: number }[]
  ensemble: { members: string[]; fpr: number; balanced_accuracy: number }
  fpr_budget: number
}

export interface AdversaryData {
  attackers: { attack: string; tier: 'white' | 'grey' | 'black'; label: string }[]
  tiers: { attack: string; tier: string; spec: string; value: number; lo: number; hi: number }[]
  flows: { attack: string; spec: string; n: number; passes_validator: number; evasion: number; pass_and_evade: number; pop10: number; pop100: number }[]
  by_category: { attack: string; category: string; pass_and_evade: number }[]
  cost: { attack: string; byte_overhead: number; rate_loss: number; features_changed: number; pass_and_evade: number }[]
  projection: { spec: string; attack: string; model: string; unrealizable: number; evasion_before: number; evasion_after: number; pae_after: number }[]
  levers: { attack: string; wins: number; 'younger_%': number; 'longer_%': number; 'padding_%': number; 'throttling_%': number; 'ttl_%': number; median_lifetime: number }[]
  n_source_rows: number
  specs: Record<string, { label: string; knobs: string[] }>
}

export interface PipelineData {
  rows_in_file: number; distinct_rows: number; exact_duplicates: number; conflicting: number
  rows_kept: number; cap_per_class: number; csv_gb: number; split: string
  n_features: number; features_before: number; constant_columns: string[]; dropped_columns: string[]; log1p_columns: string[]
  classes: { class: string; category: string; raw: number; kept: number; train: number; val: number; test: number }[]
  leakage: { test_rows: number; identical_to_train: number; flagged_features: number; top_single_feature: { feature: string; bal_acc: number }[] }
}

export interface BasePaperData {
  citation: { title: string; authors: string; venue: string; doi: string; dataset: string; adversarial_samples: number }
  nids_clean: { rows: { model: string; accuracy: number; val_accuracy: number; train_loss: number; val_loss: number; f1: number }[] }
  nids_under_attack: { rows: { model: string; accuracy: number; f1: number; attack_success: number }[] }
  discriminator: { rows: { classifier: string; accuracy: number; precision: number; recall: number; f1: number; approx?: boolean }[] }
  eids_by_attack: { rows: { attack: string; success_before: number; success_after: number; acc_before: number; acc_after: number; f1_before: number; f1_after: number }[] }
  mixed_scenario: { rows: { model: string; accuracy: number; recall: number; f1: number }[] }
}
