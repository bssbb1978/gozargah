import { buildAdaptiveProtocolPlan } from '../ai/protocol-controller';
import { buildAdaptiveProtocolPolicy } from '../protocols/policy';
import { protocolCatalog } from '../protocols/catalog';
import { defaultEdgeLearner } from '../ai/edge-learner';

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
console.log('protocol-controller: ok');
