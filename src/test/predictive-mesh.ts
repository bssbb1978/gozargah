import { assessHealth } from "../ai/predictive-mesh";

const now = 100_000;
const improving = Array.from({ length: 12 }, (_, i) => ({ ts: now - (11 - i) * 60_000, ok: i >= 3, latencyMs: 400 - i * 20 }));
const degrading = Array.from({ length: 12 }, (_, i) => ({ ts: now - (11 - i) * 60_000, ok: i < 9, latencyMs: 100 + i * 35 }));
const a = assessHealth(improving, now);
const b = assessHealth(degrading, now);
if (a.drift !== "improving") throw new Error("predictive improvement detection failed");
if (b.drift !== "degrading") throw new Error("predictive degradation detection failed");
if (!(b.forecastSuccess < a.forecastSuccess)) throw new Error("forecast ordering failed");
console.log("predictive-mesh: ok");
