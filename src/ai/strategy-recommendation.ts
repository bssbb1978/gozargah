/**
 * Strict, advisory-only schema for Workers AI strategy suggestions.
 *
 * Model output is never executable and never feeds the proxy data path. Every
 * value is allowlisted/clamped before it can leave this module; malformed or
 * unsupported responses are rejected so the deterministic local policy stays
 * authoritative.
 */
export const STRATEGY_RECOMMENDATION_SCHEMA = 'axr-strategy-advice/v1' as const;

export type StrategyTransport = 'ws' | 'grpc' | 'httpupgrade' | 'xhttp';
export type StrategyProfile = 'standard' | 'fragmented' | 'alt-port' | 'fragmented-alt';
export type StrategyEntryChoice = 'primary' | 'backup_1' | 'backup_2' | 'backup_3' | 'backup_4';

export interface StrategyRecommendation {
  schema: typeof STRATEGY_RECOMMENDATION_SCHEMA;
  transport: StrategyTransport;
  profile: StrategyProfile;
  entry: StrategyEntryChoice;
  sniChoice: StrategyEntryChoice;
  fragment: { enabled: boolean; minBytes: number; maxBytes: number; gapMs: number };
  retry: { maxAttempts: number; baseDelayMs: number; maxDelayMs: number };
}

export interface StrategyConstraints {
  transports: readonly string[];
  entries: readonly string[];
  sniChoices: readonly string[];
}

const PROFILE_SET = new Set<StrategyProfile>(['standard', 'fragmented', 'alt-port', 'fragmented-alt']);
const TRANSPORT_SET = new Set<StrategyTransport>(['ws', 'grpc', 'httpupgrade', 'xhttp']);
const ENTRY_SET = new Set<StrategyEntryChoice>(['primary', 'backup_1', 'backup_2', 'backup_3', 'backup_4']);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function boundedInteger(value: unknown, min: number, max: number): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return Math.max(min, Math.min(max, Math.floor(value)));
}

/** Validate and normalize untrusted model JSON against installed capabilities. */
export function validateStrategyRecommendation(value: unknown, constraints: StrategyConstraints): StrategyRecommendation | null {
  if (!isRecord(value) || !hasExactKeys(value, ['schema', 'transport', 'profile', 'entry', 'sniChoice', 'fragment', 'retry'])) return null;
  if (value.schema !== STRATEGY_RECOMMENDATION_SCHEMA) return null;
  if (typeof value.transport !== 'string' || !TRANSPORT_SET.has(value.transport as StrategyTransport) || !constraints.transports.includes(value.transport)) return null;
  if (typeof value.profile !== 'string' || !PROFILE_SET.has(value.profile as StrategyProfile)) return null;
  if (typeof value.entry !== 'string' || !ENTRY_SET.has(value.entry as StrategyEntryChoice) || !constraints.entries.includes(value.entry)) return null;
  if (typeof value.sniChoice !== 'string' || !ENTRY_SET.has(value.sniChoice as StrategyEntryChoice) || !constraints.sniChoices.includes(value.sniChoice)) return null;

  if (!isRecord(value.fragment) || !hasExactKeys(value.fragment, ['enabled', 'minBytes', 'maxBytes', 'gapMs']) || typeof value.fragment.enabled !== 'boolean') return null;
  const minBytes = boundedInteger(value.fragment.minBytes, 128, 4096);
  const proposedMax = boundedInteger(value.fragment.maxBytes, 128, 16_384);
  const gapMs = boundedInteger(value.fragment.gapMs, 0, 250);
  if (minBytes === null || proposedMax === null || gapMs === null) return null;
  const maxBytes = Math.max(minBytes, proposedMax);

  if (!isRecord(value.retry) || !hasExactKeys(value.retry, ['maxAttempts', 'baseDelayMs', 'maxDelayMs'])) return null;
  const maxAttempts = boundedInteger(value.retry.maxAttempts, 1, 8);
  const baseDelayMs = boundedInteger(value.retry.baseDelayMs, 100, 30_000);
  const proposedDelay = boundedInteger(value.retry.maxDelayMs, 100, 120_000);
  if (maxAttempts === null || baseDelayMs === null || proposedDelay === null) return null;
  const maxDelayMs = Math.max(baseDelayMs, proposedDelay);

  return {
    schema: STRATEGY_RECOMMENDATION_SCHEMA,
    transport: value.transport as StrategyTransport,
    profile: value.profile as StrategyProfile,
    entry: value.entry as StrategyEntryChoice,
    sniChoice: value.sniChoice as StrategyEntryChoice,
    fragment: { enabled: value.fragment.enabled, minBytes, maxBytes, gapMs },
    retry: { maxAttempts, baseDelayMs, maxDelayMs },
  };
}

/** Parse JSON only; prose, Markdown fences, and unknown fields are rejected. */
export function parseStrategyRecommendation(text: string, constraints: StrategyConstraints): StrategyRecommendation | null {
  if (text.length > 4096) return null;
  try {
    return validateStrategyRecommendation(JSON.parse(text) as unknown, constraints);
  } catch {
    return null;
  }
}
