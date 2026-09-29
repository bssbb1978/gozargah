import { describe, expect, it } from 'vitest';
import {
  parseStrategyRecommendation,
  STRATEGY_RECOMMENDATION_SCHEMA,
  StrategyConstraints,
} from '../ai/strategy-recommendation';

const constraints: StrategyConstraints = {
  transports: ['ws', 'grpc'],
  entries: ['primary', 'backup_1'],
  sniChoices: ['primary', 'backup_1'],
};

function recommendation(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: STRATEGY_RECOMMENDATION_SCHEMA,
    transport: 'ws',
    profile: 'fragmented',
    entry: 'backup_1',
    sniChoice: 'primary',
    fragment: { enabled: true, minBytes: 256, maxBytes: 1200, gapMs: 15 },
    retry: { maxAttempts: 4, baseDelayMs: 500, maxDelayMs: 8000 },
    ...overrides,
  };
}

describe('strict strategy recommendation schema', () => {
  it('accepts a valid configured strategy using only allowlisted aliases', () => {
    expect(parseStrategyRecommendation(JSON.stringify(recommendation()), constraints)).toEqual(recommendation());
  });

  it('clamps numeric fields to safe bounds and keeps max values above min values', () => {
    const value = recommendation({
      fragment: { enabled: true, minBytes: 999_999, maxBytes: 128, gapMs: -50 },
      retry: { maxAttempts: 100, baseDelayMs: 90_000, maxDelayMs: 1000 },
    });
    expect(parseStrategyRecommendation(JSON.stringify(value), constraints)).toMatchObject({
      fragment: { minBytes: 4096, maxBytes: 4096, gapMs: 0 },
      retry: { maxAttempts: 8, baseDelayMs: 30_000, maxDelayMs: 30_000 },
    });
  });

  it('rejects prose, malformed JSON, wrong schema, extra keys, and non-integer numeric types', () => {
    expect(parseStrategyRecommendation('Use grpc and retry forever', constraints)).toBeNull();
    expect(parseStrategyRecommendation('{', constraints)).toBeNull();
    expect(parseStrategyRecommendation(JSON.stringify(recommendation({ schema: 'v9' })), constraints)).toBeNull();
    expect(parseStrategyRecommendation(JSON.stringify(recommendation({ execute: 'raw-model-instruction' })), constraints)).toBeNull();
    expect(parseStrategyRecommendation(JSON.stringify(recommendation({ fragment: { enabled: true, minBytes: '256', maxBytes: 1200, gapMs: 15 } })), constraints)).toBeNull();
  });

  it('rejects unsupported transports and arbitrary host/SNI values', () => {
    expect(parseStrategyRecommendation(JSON.stringify(recommendation({ transport: 'xhttp' })), constraints)).toBeNull();
    expect(parseStrategyRecommendation(JSON.stringify(recommendation({ entry: 'https://attacker.example' })), constraints)).toBeNull();
    expect(parseStrategyRecommendation(JSON.stringify(recommendation({ sniChoice: 'attacker.example' })), constraints)).toBeNull();
  });

  it('rejects oversized output rather than parsing an unbounded model response', () => {
    expect(parseStrategyRecommendation(' '.repeat(4097), constraints)).toBeNull();
  });
});
