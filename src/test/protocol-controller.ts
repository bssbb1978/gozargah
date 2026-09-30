import { buildAdaptiveProtocolPlan } from '../ai/protocol-controller';
import { buildAdaptiveProtocolPolicy } from '../protocols/policy';
import { protocolCatalog } from '../protocols/catalog';
import { defaultEdgeLearner } from '../ai/edge-learner';
import { assessRegime, type RegimeAssessment } from '../ai/regime';

const profiles = buildAdaptiveProtocolPolicy(protocolCatalog(true));
const plan = buildAdaptiveProtocolPlan({
  profiles,
  learner: defaultEdgeLearner(1_000),
  predictive: {},
  networkState: { state: 'recovery', quorum: 0.25, healthy: 0, degraded: 1, quarantined: 3, unknown: 0, total: 4, failureRate: 0.9, confidence: 0.8, anomalyScore: 0.9, signalClass: 'broad_degradation', selectedPath: null, reasonCodes: ['low_usable_quorum'], generatedAt: 1_000 },
  limit: 8,
  now: 2_000,
});
if (!plan.selected) throw new Error('plan should select a profile');
if (plan.fallbackLadder.length < 2) throw new Error('fallback ladder too short');
if (plan.diversity.transports.length < 2) throw new Error('transport diversity missing');
if (!plan.reasonCodes.includes('network_recovery_bias')) throw new Error('recovery bias missing');
if (!/^[0-9a-f]{8}$/.test(plan.policyFingerprint)) throw new Error('bad policy fingerprint');

// Opt-in AI transport preference is a score hint, not an override of the plan.
const wsCapability = profiles.find((p) => p.ready && p.transport === 'ws');
const grpcCapability = profiles.find((p) => p.ready && p.transport === 'grpc');
if (!wsCapability || !grpcCapability) throw new Error('transport preference fixture unavailable');
const preferenceProfiles = [
  { ...wsCapability, id: 'a-ws', protocol: 'vless' as const, score: 50 },
  { ...grpcCapability, id: 'z-grpc', protocol: 'vless' as const, score: 50 },
];
const preferredPlan = buildAdaptiveProtocolPlan({ profiles: preferenceProfiles, preferredTransport: 'grpc', now: 2_000, limit: 2 });
if (preferredPlan.selected !== 'z-grpc' || !preferredPlan.reasonCodes.includes('ai_advisor_transport_preference')) {
  throw new Error('bounded AI transport preference was not applied to the capability-ready candidate');
}
const localPlan = buildAdaptiveProtocolPlan({ profiles: preferenceProfiles, now: 2_000, limit: 2 });
if (localPlan.selected !== 'a-ws') throw new Error('default local ranking should remain authoritative without opt-in preference');

// 2.12 regime: a calm network with a suspected aggregate regime change must
// upgrade strategy to diversify and carry the reason code.
const calmNet = { state: 'healthy' as const, quorum: 0.9, healthy: 3, degraded: 0, quarantined: 0, unknown: 0, total: 4, failureRate: 0.05, confidence: 0.8, anomalyScore: 0.1, signalClass: 'normal' as const, selectedPath: 'a', reasonCodes: ['healthy_quorum'], generatedAt: 2_000 };
const calmPlan = buildAdaptiveProtocolPlan({ profiles, networkState: calmNet, limit: 8, now: 2_000 });
if (calmPlan.strategy !== 'stable') throw new Error('calm network should be stable, got ' + calmPlan.strategy);
if (calmPlan.regimeState !== 'stable') throw new Error('default regime label should be stable');

const T0 = 1_700_000_000_000;
const MIN = 60_000;
const regimeSamples = [
  ...Array.from({ length: 20 }, (_, i) => ({ ok: true, latencyMs: 120, ts: T0 - 89 * MIN + i * 2 * MIN })),
  ...Array.from({ length: 10 }, (_, i) => ({ ok: false, latencyMs: 3000, ts: T0 - 29 * MIN + i * 2 * MIN })),
];
const regime: RegimeAssessment = assessRegime(regimeSamples, T0);
if (regime.state !== 'suspected_change') throw new Error('test regime fixture should be suspected_change');
const regimePlan = buildAdaptiveProtocolPlan({ profiles, networkState: calmNet, regime, limit: 8, now: T0 });
if (regimePlan.strategy !== 'diversify') throw new Error('suspected regime change should diversify, got ' + regimePlan.strategy);
if (!regimePlan.reasonCodes.includes('suspected_regime_change')) throw new Error('suspected_regime_change reason missing');
if (regimePlan.regimeState !== 'suspected_change' || regimePlan.regimeConfidence <= 0) throw new Error('regime metadata missing from plan');
console.log('protocol-controller: ok');
