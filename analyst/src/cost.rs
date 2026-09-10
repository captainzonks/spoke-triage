// ==============================================================================
// cost.rs - per-call cost estimation
// ==============================================================================
// Description: Pricing per docs/spec.md §9/§11, verified live against
//              platform.claude.com/docs on 2026-09-09. Anthropic has no
//              pricing API, so this table is necessarily hardcoded — re-check
//              the source before adding a model or trusting stale numbers.
// Author: Matt Barham
// Created: 2026-09-09
// Modified: 2026-09-09
// Version: 0.1.0
// ==============================================================================

pub struct ModelPricing {
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
    /// 5-minute ephemeral cache write; this client always uses 5m TTL.
    pub cache_write_per_mtok: f64,
    pub cache_read_per_mtok: f64,
}

pub fn pricing_for(model: &str) -> Option<ModelPricing> {
    match model {
        "claude-haiku-4-5" | "claude-haiku-4-5-20251001" => Some(ModelPricing {
            input_per_mtok: 1.0,
            output_per_mtok: 5.0,
            cache_write_per_mtok: 1.25,
            cache_read_per_mtok: 0.10,
        }),
        "claude-sonnet-5" => Some(ModelPricing {
            input_per_mtok: 2.0,
            output_per_mtok: 10.0,
            cache_write_per_mtok: 2.50,
            cache_read_per_mtok: 0.20,
        }),
        _ => None,
    }
}

pub fn estimate_cost_usd(
    model: &str,
    input_tokens: i64,
    output_tokens: i64,
    cache_write_tokens: i64,
    cache_read_tokens: i64,
) -> f64 {
    let Some(p) = pricing_for(model) else {
        return 0.0;
    };
    let mtok = 1_000_000.0;
    (input_tokens as f64 / mtok) * p.input_per_mtok
        + (output_tokens as f64 / mtok) * p.output_per_mtok
        + (cache_write_tokens as f64 / mtok) * p.cache_write_per_mtok
        + (cache_read_tokens as f64 / mtok) * p.cache_read_per_mtok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn haiku_cost_matches_pricing_table() {
        let cost = estimate_cost_usd("claude-haiku-4-5", 1_000_000, 1_000_000, 0, 0);
        assert!((cost - 6.0).abs() < 1e-9);
    }

    #[test]
    fn cache_read_is_far_cheaper_than_base_input() {
        let base = estimate_cost_usd("claude-haiku-4-5", 1_000_000, 0, 0, 0);
        let cached = estimate_cost_usd("claude-haiku-4-5", 0, 0, 0, 1_000_000);
        assert!(cached < base / 5.0);
    }

    #[test]
    fn unknown_model_costs_zero_not_a_crash() {
        assert_eq!(estimate_cost_usd("some-future-model", 1000, 1000, 0, 0), 0.0);
    }
}
