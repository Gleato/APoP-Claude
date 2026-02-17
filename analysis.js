/**
 * CLNP Server-Side Analysis Engine
 *
 * AGENT COOKIE CRUMB: This module contains the analysis and scoring logic
 * extracted from the client-side clnp-probe.html. It lives server-side so that:
 *   1. Scoring thresholds and weights are SECRET — never sent to clients
 *   2. Target positions are reconstructed from challenge params — client data not trusted
 *   3. Population statistics can be maintained in the future
 *
 * The module exports a single function: analyze(rawData, challengeParams)
 * It reconstructs what the target was doing from the challenge params, then
 * runs all 8 biomechanical analysis pipelines on the raw pointer data.
 */

"use strict";

// ─── SERVER-SECRET SCORING CONFIG ───────────────────────────
// AGENT COOKIE CRUMB: These thresholds NEVER leave the server.
// An attacker reading the open-source client code cannot see what
// values the server considers "human". These can also be updated
// adaptively based on population data without any client changes.
const ScoringConfig = {
  humanLatencyRange: [120, 380],
  humanLatencySD: [15, 180],
  humanTremorRatioMin: 0.005,
  human1fSlopeRange: [-2.5, 0.0],
  humanSDNSlopeMin: 0.05,
  humanCrossAxisMin: 0.03,
  humanCogInterferenceMin: 0.03,
  tremorBandLow: 8,
  tremorBandHigh: 12,

  // Scoring weights — also secret
  weights: {
    transferFn: 3.0,
    tremor: 2.5,
    oneOverF: 2.0,
    signalDepNoise: 2.5,
    crossAxis: 2.0,
    pulseResponse: 3.0,
    cogInterference: 2.0,
    minJerk: 1.5,
  },

  // Verdict thresholds
  humanThreshold: 0.65,
  uncertainThreshold: 0.35,
};


// ─── MATH ENGINE ────────────────────────────────────────────
// Pure math utilities. Identical to client version.
const MathEngine = {
  nextPow2(n) {
    let p = 1;
    while (p < n) p <<= 1;
    return p;
  },

  fft(re, im) {
    const N = re.length;
    if (N <= 1) return { re: [...re], im: [...im] };
    const outRe = new Float64Array(N);
    const outIm = new Float64Array(N);
    const bits = Math.log2(N);
    for (let i = 0; i < N; i++) {
      let rev = 0;
      for (let b = 0; b < bits; b++) rev = (rev << 1) | ((i >> b) & 1);
      outRe[rev] = re[i];
      outIm[rev] = im[i];
    }
    for (let size = 2; size <= N; size *= 2) {
      const half = size / 2;
      const angle = -2 * Math.PI / size;
      for (let i = 0; i < N; i += size) {
        for (let j = 0; j < half; j++) {
          const wRe = Math.cos(angle * j);
          const wIm = Math.sin(angle * j);
          const tRe = wRe * outRe[i + j + half] - wIm * outIm[i + j + half];
          const tIm = wRe * outIm[i + j + half] + wIm * outRe[i + j + half];
          outRe[i + j + half] = outRe[i + j] - tRe;
          outIm[i + j + half] = outIm[i + j] - tIm;
          outRe[i + j] += tRe;
          outIm[i + j] += tIm;
        }
      }
    }
    return { re: Array.from(outRe), im: Array.from(outIm) };
  },

  psd(signal, sampleRate) {
    const N = this.nextPow2(signal.length);
    const re = new Array(N).fill(0);
    const im = new Array(N).fill(0);
    for (let i = 0; i < signal.length; i++) {
      const w = 0.5 * (1 - Math.cos(2 * Math.PI * i / (signal.length - 1)));
      re[i] = signal[i] * w;
    }
    const spec = this.fft(re, im);
    const halfN = N / 2;
    const freqs = [];
    const power = [];
    for (let i = 0; i < halfN; i++) {
      freqs.push(i * sampleRate / N);
      power.push((spec.re[i] ** 2 + spec.im[i] ** 2) / N);
    }
    return { freqs, power };
  },

  transferFunction(input, output, sampleRate) {
    const N = this.nextPow2(Math.max(input.length, output.length));
    const xRe = new Array(N).fill(0);
    const xIm = new Array(N).fill(0);
    const yRe = new Array(N).fill(0);
    const yIm = new Array(N).fill(0);
    const len = Math.min(input.length, output.length);
    for (let i = 0; i < len; i++) {
      const w = 0.5 * (1 - Math.cos(2 * Math.PI * i / (len - 1)));
      xRe[i] = input[i] * w;
      yRe[i] = output[i] * w;
    }
    const X = this.fft(xRe, xIm);
    const Y = this.fft(yRe, yIm);
    const halfN = N / 2;
    const magnitude = [], phase = [], coherence = [], freqs = [];
    for (let i = 0; i < halfN; i++) {
      freqs.push(i * sampleRate / N);
      const sxyRe = X.re[i] * Y.re[i] + X.im[i] * Y.im[i];
      const sxyIm = X.re[i] * Y.im[i] - X.im[i] * Y.re[i];
      const sxx = X.re[i] ** 2 + X.im[i] ** 2 + 1e-12;
      const syy = Y.re[i] ** 2 + Y.im[i] ** 2 + 1e-12;
      const hRe = sxyRe / sxx;
      const hIm = sxyIm / sxx;
      magnitude.push(Math.sqrt(hRe ** 2 + hIm ** 2));
      phase.push(Math.atan2(hIm, hRe));
      coherence.push((sxyRe ** 2 + sxyIm ** 2) / (sxx * syy));
    }
    return { freqs, magnitude, phase, coherence };
  },

  stats(arr) {
    if (!arr.length) return { mean: 0, std: 0, min: 0, max: 0 };
    const n = arr.length;
    const mean = arr.reduce((a, b) => a + b, 0) / n;
    const variance = arr.reduce((a, b) => a + (b - mean) ** 2, 0) / n;
    return { mean, std: Math.sqrt(variance), min: Math.min(...arr), max: Math.max(...arr) };
  },

  linReg(xs, ys) {
    const n = xs.length;
    if (n < 2) return { slope: 0, intercept: 0, r2: 0 };
    let sx = 0, sy = 0, sxy = 0, sxx = 0;
    for (let i = 0; i < n; i++) {
      sx += xs[i]; sy += ys[i];
      sxy += xs[i] * ys[i]; sxx += xs[i] ** 2;
    }
    const denom = n * sxx - sx * sx;
    if (Math.abs(denom) < 1e-12) return { slope: 0, intercept: 0, r2: 0 };
    const slope = (n * sxy - sx * sy) / denom;
    const intercept = (sy - slope * sx) / n;
    const ssRes = ys.reduce((a, y, i) => a + (y - (slope * xs[i] + intercept)) ** 2, 0);
    const ssTot = ys.reduce((a, y) => a + (y - sy / n) ** 2, 0);
    const r2 = ssTot > 0 ? 1 - ssRes / ssTot : 0;
    return { slope, intercept, r2 };
  },

  correlation(xs, ys) {
    const n = Math.min(xs.length, ys.length);
    if (n < 3) return 0;
    const mx = xs.reduce((a, b) => a + b, 0) / n;
    const my = ys.reduce((a, b) => a + b, 0) / n;
    let num = 0, dx2 = 0, dy2 = 0;
    for (let i = 0; i < n; i++) {
      const dx = xs[i] - mx;
      const dy = ys[i] - my;
      num += dx * dy; dx2 += dx * dx; dy2 += dy * dy;
    }
    const denom = Math.sqrt(dx2 * dy2);
    return denom > 0 ? num / denom : 0;
  },

  velocity(positions, timestamps) {
    const vel = [];
    for (let i = 1; i < positions.length; i++) {
      const dt = (timestamps[i] - timestamps[i - 1]) / 1000;
      if (dt > 0) vel.push((positions[i] - positions[i - 1]) / dt);
    }
    return vel;
  },

  resample(values, timestamps, targetRate) {
    if (values.length < 2) return { values: [...values], timestamps: [...timestamps] };
    const t0 = timestamps[0];
    const tEnd = timestamps[timestamps.length - 1];
    const dt = 1000 / targetRate;
    const out = [], outT = [];
    let srcIdx = 0;
    for (let t = t0; t <= tEnd; t += dt) {
      while (srcIdx < timestamps.length - 2 && timestamps[srcIdx + 1] < t) srcIdx++;
      const t1 = timestamps[srcIdx];
      const t2 = timestamps[srcIdx + 1] || t1 + 1;
      const frac = (t2 > t1) ? (t - t1) / (t2 - t1) : 0;
      out.push(values[srcIdx] + frac * ((values[srcIdx + 1] || values[srcIdx]) - values[srcIdx]));
      outT.push(t);
    }
    return { values: out, timestamps: outT };
  },
};


// ─── TARGET RECONSTRUCTION ──────────────────────────────────
// AGENT COOKIE CRUMB: The server independently reconstructs where
// the target was at each timestamp using the challenge parameters.
// This means the client's reported targetX/Y are NOT trusted — the
// server computes them from first principles.

/**
 * Compute perturbation at a given time using challenge parameters.
 * Mirrors PerturbEngine.get(t) but uses server-provided params.
 */
function computePerturbation(t, trackingStart, probes, pulses, pulseHoldDuration, pulseReturnDuration) {
  let px = 0, py = 0;
  let isPulse = false;
  let pulseIndex = -1;

  // Multi-sine component
  const elapsed = (t - trackingStart) / 1000;
  for (const probe of probes) {
    const phase = 2 * Math.PI * probe.freq * elapsed;
    px += probe.ampX * Math.sin(phase);
    py += probe.ampY * Math.sin(phase + probe.phaseOffset);
  }

  // Pulse component
  for (let i = 0; i < pulses.length; i++) {
    const pulse = pulses[i];
    const pulseAbsTime = trackingStart + pulse.offsetMs;
    if (t < pulseAbsTime) continue;
    const dt = t - pulseAbsTime;
    if (dt < pulseHoldDuration) {
      px += pulse.ampX;
      py += pulse.ampY;
      isPulse = true;
      pulseIndex = i;
    } else if (dt < pulseHoldDuration + pulseReturnDuration) {
      const frac = (dt - pulseHoldDuration) / pulseReturnDuration;
      const ease = 1 - frac * frac;
      px += pulse.ampX * ease;
      py += pulse.ampY * ease;
    }
  }

  return { x: px, y: py, isPulse, pulseIndex };
}

/**
 * Reconstruct tracking data: for each pointer sample, compute what the
 * target and perturbation were at that exact timestamp.
 */
function reconstructTracking(pointer, phases, challenge, canvasSize) {
  const { path, perturbation } = challenge;
  const cx = canvasSize.width / 2;
  const cy = canvasSize.height / 2;
  const ax = canvasSize.width * path.padding;
  const ay = canvasSize.height * path.padding;
  const trackingDuration = challenge.trackingDuration;

  const tracking = [];
  for (const [t, x, y] of pointer) {
    if (t < phases.trackingStart) continue; // skip free move

    // Compute pathTime — mirrors PhaseCtrl._tickTracking logic exactly
    let pathTime;
    if (t < phases.dualtaskStart) {
      pathTime = t - phases.trackingStart;
    } else {
      pathTime = trackingDuration + (t - phases.dualtaskStart);
    }

    // Smooth Lissajous path
    const smoothX = cx + ax * Math.sin(2 * Math.PI * path.freqX * (pathTime / 1000) + path.phase);
    const smoothY = cy + ay * Math.sin(2 * Math.PI * path.freqY * (pathTime / 1000));

    // Perturbation
    const pert = computePerturbation(
      t, phases.trackingStart,
      perturbation.probes, perturbation.pulses,
      perturbation.pulseHoldDuration, perturbation.pulseReturnDuration
    );

    tracking.push({
      t, x, y,
      targetX: smoothX + pert.x,
      targetY: smoothY + pert.y,
      pertX: pert.x,
      pertY: pert.y,
      isPulse: pert.isPulse,
      pulseIdx: pert.pulseIndex,
    });
  }
  return tracking;
}


// ─── ANALYSIS HELPERS ───────────────────────────────────────

function resampleTracking(data, targetRate) {
  if (data.length < 4) return null;
  const resX = MathEngine.resample(data.map(d => d.x), data.map(d => d.t), targetRate);
  const resY = MathEngine.resample(data.map(d => d.y), data.map(d => d.t), targetRate);
  const resTX = MathEngine.resample(data.map(d => d.targetX), data.map(d => d.t), targetRate);
  const resTY = MathEngine.resample(data.map(d => d.targetY), data.map(d => d.t), targetRate);
  const resPX = MathEngine.resample(data.map(d => d.pertX), data.map(d => d.t), targetRate);
  const resPY = MathEngine.resample(data.map(d => d.pertY), data.map(d => d.t), targetRate);
  return resX.values.map((_, i) => ({
    t: resX.timestamps[i], x: resX.values[i], y: resY.values[i],
    targetX: resTX.values[i], targetY: resTY.values[i],
    pertX: resPX.values[i], pertY: resPY.values[i],
  }));
}

function movingAvg(arr, windowSize) {
  const result = [];
  for (let i = 0; i < arr.length; i++) {
    const start = Math.max(0, i - Math.floor(windowSize / 2));
    const end = Math.min(arr.length, i + Math.floor(windowSize / 2) + 1);
    let sum = 0;
    for (let j = start; j < end; j++) sum += arr[j];
    result.push(sum / (end - start));
  }
  return result;
}


// ─── 8 ANALYSIS PIPELINES ──────────────────────────────────

function analyzeTransferFunction(tracking, sampleRate, probeFreqs) {
  if (tracking.length < 64) return { valid: false };
  const resampled = resampleTracking(tracking, sampleRate);
  if (!resampled || resampled.length < 64) return { valid: false };

  const pertX = resampled.map(d => d.pertX);
  const cursorMinusSmooth = resampled.map(d => d.x - (d.targetX - d.pertX));
  const tf = MathEngine.transferFunction(pertX, cursorMinusSmooth, sampleRate);

  const probeResults = [];
  for (const freq of probeFreqs) {
    const binIdx = Math.round(freq * tf.freqs.length * 2 / sampleRate);
    if (binIdx >= 0 && binIdx < tf.magnitude.length) {
      probeResults.push({ freq, gain: tf.magnitude[binIdx], phase: tf.phase[binIdx], coherence: tf.coherence[binIdx] });
    }
  }

  let rolloffScore = 0;
  for (let i = 1; i < probeResults.length; i++) {
    if (probeResults[i].gain < probeResults[i - 1].gain) rolloffScore++;
  }
  const hasRolloff = rolloffScore >= 2;

  const delays = [];
  const coherentProbes = [];
  for (const pr of probeResults) {
    if (pr.coherence > 0.15 && pr.freq > 0) {
      const delay = -pr.phase / (2 * Math.PI * pr.freq) * 1000;
      if (delay > 0 && delay < 1000) {
        delays.push({ delay, weight: pr.coherence });
        coherentProbes.push(pr);
      }
    }
  }
  let meanDelay = null;
  if (delays.length > 0) {
    const totalW = delays.reduce((a, d) => a + d.weight, 0);
    meanDelay = delays.reduce((a, d) => a + d.delay * d.weight, 0) / totalW;
  }
  const hasPhaseDelay = meanDelay !== null && meanDelay > 50;
  const delayPlausible = meanDelay !== null && meanDelay > 30 && meanDelay < 500;

  return { valid: true, probeResults, hasRolloff, hasPhaseDelay, meanDelay, delayPlausible, coherentProbeCount: coherentProbes.length };
}

function analyzeTremor(tracking, sampleRate) {
  if (tracking.length < 64 || sampleRate < 20) return { valid: false };
  const rate = Math.min(sampleRate, 120);
  const resampled = resampleTracking(tracking, rate);
  if (!resampled || resampled.length < 64) return { valid: false };

  const velX = MathEngine.velocity(resampled.map(d => d.x), resampled.map(d => d.t));
  const velY = MathEngine.velocity(resampled.map(d => d.y), resampled.map(d => d.t));
  const speed = velX.map((vx, i) => Math.sqrt(vx ** 2 + (velY[i] || 0) ** 2));
  const smoothed = movingAvg(speed, Math.round(rate / 3));
  const residual = speed.map((s, i) => s - (smoothed[i] || 0));
  const psdResult = MathEngine.psd(residual, rate);

  let tremorPower = 0, totalPower = 0, peakFreq = 0, peakPow = 0;
  for (let i = 0; i < psdResult.freqs.length; i++) {
    const f = psdResult.freqs[i], p = psdResult.power[i];
    if (f > 1) totalPower += p;
    if (f >= ScoringConfig.tremorBandLow && f <= ScoringConfig.tremorBandHigh) {
      tremorPower += p;
      if (p > peakPow) { peakPow = p; peakFreq = f; }
    }
  }
  return { valid: true, tremorRatio: totalPower > 0 ? tremorPower / totalPower : 0, peakFrequency: peakFreq, tremorPower, totalPower };
}

function analyzeAccelTremor(accel) {
  if (!accel || accel.length < 64) return { valid: false };
  const dts = [];
  for (let i = 1; i < Math.min(accel.length, 500); i++) dts.push(accel[i][0] - accel[i - 1][0]);
  const avgDt = dts.reduce((a, b) => a + b, 0) / dts.length;
  const rate = avgDt > 0 ? 1000 / avgDt : 60;
  if (rate < 20) return { valid: false };

  const magnitudes = accel.map(s => Math.sqrt(s[1] ** 2 + s[2] ** 2 + s[3] ** 2));
  const timestamps = accel.map(s => s[0]);
  const targetRate = Math.min(rate, 100);
  const resampled = MathEngine.resample(magnitudes, timestamps, targetRate);
  if (resampled.values.length < 64) return { valid: false };

  const smoothed = movingAvg(resampled.values, Math.round(targetRate / 3));
  const residual = resampled.values.map((v, i) => v - (smoothed[i] || 0));
  const psdResult = MathEngine.psd(residual, targetRate);

  let tremorPower = 0, totalPower = 0, peakFreq = 0, peakPow = 0;
  for (let i = 0; i < psdResult.freqs.length; i++) {
    const f = psdResult.freqs[i], p = psdResult.power[i];
    if (f > 1) totalPower += p;
    if (f >= ScoringConfig.tremorBandLow && f <= ScoringConfig.tremorBandHigh) {
      tremorPower += p;
      if (p > peakPow) { peakPow = p; peakFreq = f; }
    }
  }
  return { valid: true, tremorRatio: totalPower > 0 ? tremorPower / totalPower : 0, peakFrequency: peakFreq, sampleRate: rate, sampleCount: accel.length };
}

function analyze1fNoise(tracking, sampleRate) {
  if (tracking.length < 128) return { valid: false };
  const resampled = resampleTracking(tracking, sampleRate);
  if (!resampled || resampled.length < 128) return { valid: false };
  const errorX = resampled.map(d => d.x - d.targetX);
  const errorVelX = MathEngine.velocity(errorX, resampled.map(d => d.t));
  if (errorVelX.length < 64) return { valid: false };
  const psdResult = MathEngine.psd(errorVelX, sampleRate);
  const logF = [], logP = [];
  for (let i = 0; i < psdResult.freqs.length; i++) {
    const f = psdResult.freqs[i], p = psdResult.power[i];
    if (f >= 0.3 && f <= sampleRate / 4 && p > 0) {
      logF.push(Math.log10(f)); logP.push(Math.log10(p));
    }
  }
  const reg = MathEngine.linReg(logF, logP);
  return { valid: true, slope: reg.slope, r2: reg.r2 };
}

function analyzeSignalDepNoise(tracking) {
  if (tracking.length < 100) return { valid: false };
  const windowSize = 15;
  const speeds = [], variabilities = [];
  for (let i = windowSize; i < tracking.length - windowSize; i += Math.max(1, Math.floor(windowSize / 2))) {
    const win = tracking.slice(i - windowSize, i + windowSize);
    let totalSpeed = 0;
    const errors = [];
    for (let j = 1; j < win.length; j++) {
      const dt = (win[j].t - win[j - 1].t) / 1000;
      if (dt > 0) totalSpeed += Math.sqrt(((win[j].x - win[j - 1].x) / dt) ** 2 + ((win[j].y - win[j - 1].y) / dt) ** 2);
      errors.push(Math.sqrt((win[j].x - win[j].targetX) ** 2 + (win[j].y - win[j].targetY) ** 2));
    }
    const avgSpeed = totalSpeed / (win.length - 1);
    if (avgSpeed > 10) {
      speeds.push(avgSpeed);
      variabilities.push(MathEngine.stats(errors).std);
    }
  }
  if (speeds.length < 10) return { valid: false };
  return { valid: true, slope: MathEngine.linReg(speeds, variabilities).slope, correlation: MathEngine.correlation(speeds, variabilities), r2: MathEngine.linReg(speeds, variabilities).r2 };
}

function analyzeCrossAxis(tracking, pulses, trackingStart) {
  const triggeredPulses = pulses.filter(p => {
    const absTime = trackingStart + p.offsetMs;
    return tracking.some(d => d.t >= absTime);
  });
  if (triggeredPulses.length < 3) return { valid: false };

  const couplingValues = [];
  for (const pulse of triggeredPulses) {
    const absTime = trackingStart + pulse.offsetMs;
    const win = tracking.filter(d => d.t >= absTime && d.t < absTime + 400);
    if (win.length < 5) continue;
    const dx = win[win.length - 1].x - win[0].x;
    const dy = win[win.length - 1].y - win[0].y;
    if (Math.abs(dx) > 2) couplingValues.push(Math.abs(dy / dx));
  }
  if (couplingValues.length < 2) return { valid: false };
  const stats = MathEngine.stats(couplingValues);
  return { valid: true, meanCoupling: stats.mean, stdCoupling: stats.std };
}

function analyzePulseResponses(tracking, pulses, trackingStart) {
  const responses = [];
  for (const pulse of pulses) {
    const absTime = trackingStart + pulse.offsetMs;
    const baseline = tracking.filter(d => d.t >= absTime - 200 && d.t < absTime);
    const win = tracking.filter(d => d.t >= absTime && d.t < absTime + 600);
    if (baseline.length < 3 || win.length < 5) continue;

    const baseX = baseline[baseline.length - 1].x;
    const pertDir = Math.sign(pulse.ampX);
    const prePulseVelX = (baseline[baseline.length - 1].x - baseline[0].x) /
      ((baseline[baseline.length - 1].t - baseline[0].t) / 1000 + 0.001);

    const normalized = win.map(d => {
      const dt = (d.t - absTime) / 1000;
      return { t: d.t - absTime, correction: ((d.x - baseX) - prePulseVelX * dt) * pertDir / Math.abs(pulse.ampX) };
    });

    const ONSET_THRESHOLD = 0.20, SUSTAIN_THRESHOLD = 0.15, SUSTAIN_DURATION = 40, MIN_LATENCY = 80;
    let latency = null;
    for (let i = 0; i < normalized.length; i++) {
      const pt = normalized[i];
      if (pt.t < MIN_LATENCY) continue;
      if (pt.correction > ONSET_THRESHOLD) {
        let sustained = true;
        for (let j = i + 1; j < normalized.length; j++) {
          if (normalized[j].t - pt.t > SUSTAIN_DURATION) break;
          if (normalized[j].correction < SUSTAIN_THRESHOLD) { sustained = false; break; }
        }
        if (sustained) { latency = pt.t; break; }
      }
    }

    const searchStart = latency || MIN_LATENCY;
    let peakCorr = 0, peakTime = 0;
    for (const pt of normalized) {
      if (pt.t >= searchStart && pt.correction > peakCorr) { peakCorr = pt.correction; peakTime = pt.t; }
    }
    const overshoot = Math.max(0, peakCorr - 1.0);
    responses.push({ latency, peakCorr, peakTime, overshoot, normalized });
  }

  if (responses.length < 2) return { valid: false };
  const latencies = responses.filter(r => r.latency !== null).map(r => r.latency);
  const latencyStats = MathEngine.stats(latencies);
  return { valid: true, responses, latencyMean: latencyStats.mean, latencyStd: latencyStats.std, latencyMin: latencyStats.min, latencyMax: latencyStats.max, meanOvershoot: MathEngine.stats(responses.map(r => r.overshoot)).mean };
}

function analyzeCogInterference(tracking, cogSchedule, dualtaskStart, cogAnswer) {
  if (!cogSchedule || cogSchedule.length < 3) return { valid: false };
  if (tracking.length < 50) return { valid: false };

  const flashEffects = [];
  for (const flash of cogSchedule) {
    const absTime = dualtaskStart + flash.offsetMs;
    const before = tracking.filter(d => d.t >= absTime - 500 && d.t < absTime);
    const after = tracking.filter(d => d.t >= absTime + 200 && d.t < absTime + 700);
    if (before.length < 3 || after.length < 3) continue;
    const errBefore = MathEngine.stats(before.map(d => Math.sqrt((d.x - d.targetX) ** 2 + (d.y - d.targetY) ** 2))).mean;
    const errAfter = MathEngine.stats(after.map(d => Math.sqrt((d.x - d.targetX) ** 2 + (d.y - d.targetY) ** 2))).mean;
    flashEffects.push({ isTarget: flash.isTarget, increase: errBefore > 0 ? (errAfter - errBefore) / errBefore : 0 });
  }
  if (flashEffects.length < 2) return { valid: false };

  const targetEffects = flashEffects.filter(f => f.isTarget);
  const nonTargetEffects = flashEffects.filter(f => !f.isTarget);
  const targetInterference = targetEffects.length > 0 ? MathEngine.stats(targetEffects.map(f => f.increase)).mean : 0;
  const nonTargetInterference = nonTargetEffects.length > 0 ? MathEngine.stats(nonTargetEffects.map(f => f.increase)).mean : 0;
  const correctAnswer = cogSchedule.filter(f => f.isTarget).length;

  return { valid: true, targetInterference, nonTargetInterference, attentionEffect: targetInterference - nonTargetInterference, correctAnswer, userAnswer: cogAnswer, flashEffects };
}

function analyzeMinJerk(pulseResult) {
  if (!pulseResult || !pulseResult.valid || pulseResult.responses.length < 2) return { valid: false };
  const r2Values = [];
  for (const resp of pulseResult.responses) {
    if (!resp.latency || resp.latency < 80 || resp.normalized.length < 8) continue;
    const moveStart = resp.latency;
    const moveEnd = resp.peakTime || resp.latency + 300;
    const movePts = resp.normalized.filter(p => p.t >= moveStart && p.t <= moveEnd);
    if (movePts.length < 4) continue;
    const t0 = movePts[0].t, tf = movePts[movePts.length - 1].t;
    const x0 = movePts[0].correction, xf = movePts[movePts.length - 1].correction;
    const dur = tf - t0;
    if (dur < 30) continue;
    let ssRes = 0, ssTot = 0;
    const meanCorr = movePts.reduce((a, p) => a + p.correction, 0) / movePts.length;
    for (const pt of movePts) {
      const tau = Math.max(0, Math.min(1, (pt.t - t0) / dur));
      const predicted = x0 + (xf - x0) * (10 * tau ** 3 - 15 * tau ** 4 + 6 * tau ** 5);
      ssRes += (pt.correction - predicted) ** 2;
      ssTot += (pt.correction - meanCorr) ** 2;
    }
    r2Values.push(ssTot > 1e-10 ? Math.max(0, 1 - ssRes / ssTot) : 0);
  }
  if (r2Values.length < 1) return { valid: false };
  return { valid: true, meanR2: MathEngine.stats(r2Values).mean, r2Values };
}


// ─── SCORER ─────────────────────────────────────────────────

function sigmoid(x, center, steepness) {
  return 1 / (1 + Math.exp(-steepness * (x - center)));
}

function rangeScore(value, low, high, steepness = 5) {
  return Math.min(1, sigmoid(value, low, steepness) * sigmoid(value, high, -steepness) * 4);
}

function scoreResults(results, inputMethod) {
  const scores = {};
  let weightedSum = 0, totalWeight = 0, validCount = 0;
  const W = ScoringConfig.weights;

  // 1. Transfer Function
  if (results.transferFn && results.transferFn.valid) {
    const tf = results.transferFn;
    let s = 0;
    if (tf.hasRolloff) s += 0.7;
    if (tf.hasPhaseDelay) s += 0.15;
    if (tf.delayPlausible) s += 0.15;
    s = Math.min(1, s);
    const delayStr = tf.meanDelay !== null ? `${tf.meanDelay.toFixed(0)}ms` : 'N/A';
    scores.transferFn = { score: s, weight: W.transferFn, label: 'Transfer Function',
      detail: `Gain rolloff: ${tf.hasRolloff ? 'YES' : 'NO'}, Est. delay: ${delayStr} (${tf.coherentProbeCount} coherent probes)` };
    weightedSum += s * W.transferFn; totalWeight += W.transferFn; validCount++;
  }

  // 2. Physiological Tremor (cursor + accelerometer hybrid)
  {
    const hasCursor = results.tremor && results.tremor.valid;
    const hasAccel = results.accelTremor && results.accelTremor.valid;
    if (hasCursor || hasAccel) {
      let cursorScore = 0, cursorDetail = '';
      if (hasCursor) {
        const tr = results.tremor;
        cursorScore = Math.min(1, tr.tremorRatio / (ScoringConfig.humanTremorRatioMin * 3));
        if (tr.peakFrequency >= 7 && tr.peakFrequency <= 13) cursorScore = Math.min(1, cursorScore + 0.2);
        cursorDetail = `Cursor: ${(tr.tremorRatio * 100).toFixed(2)}%@${tr.peakFrequency.toFixed(1)}Hz`;
      }
      let accelScore = 0, accelDetail = '';
      if (hasAccel) {
        const at = results.accelTremor;
        accelScore = Math.min(1, at.tremorRatio / (ScoringConfig.humanTremorRatioMin * 3));
        if (at.peakFrequency >= 7 && at.peakFrequency <= 13) accelScore = Math.min(1, accelScore + 0.2);
        accelDetail = `Accel: ${(at.tremorRatio * 100).toFixed(2)}%@${at.peakFrequency.toFixed(1)}Hz (${at.sampleCount} samples, ${Math.round(at.sampleRate)}Hz)`;
      }
      const s = Math.max(cursorScore, accelScore);
      const source = accelScore > cursorScore ? 'accelerometer' : 'cursor';
      const detail = [cursorDetail, accelDetail].filter(Boolean).join(' | ') + ` [best: ${source}]`;
      scores.tremor = { score: s, weight: W.tremor, label: 'Physiological Tremor', detail };
      weightedSum += s * W.tremor; totalWeight += W.tremor; validCount++;
    }
  }

  // 3. 1/f Noise
  if (results.oneOverF && results.oneOverF.valid) {
    const s = rangeScore(results.oneOverF.slope, ScoringConfig.human1fSlopeRange[0], ScoringConfig.human1fSlopeRange[1], 3);
    scores.oneOverF = { score: s, weight: W.oneOverF, label: '1/f Noise Structure',
      detail: `Velocity-domain slope: ${results.oneOverF.slope.toFixed(2)}, R²: ${results.oneOverF.r2.toFixed(2)}` };
    weightedSum += s * W.oneOverF; totalWeight += W.oneOverF; validCount++;
  }

  // 4. Signal-Dependent Noise
  if (results.signalDepNoise && results.signalDepNoise.valid) {
    const s = Math.max(0, Math.min(1, results.signalDepNoise.correlation / 0.4));
    scores.signalDepNoise = { score: s, weight: W.signalDepNoise, label: 'Signal-Dependent Noise',
      detail: `Correlation: ${results.signalDepNoise.correlation.toFixed(3)}, Slope: ${results.signalDepNoise.slope.toFixed(4)}` };
    weightedSum += s * W.signalDepNoise; totalWeight += W.signalDepNoise; validCount++;
  }

  // 5. Cross-Axis Coupling (touch-adjusted)
  if (results.crossAxis && results.crossAxis.valid) {
    const ca = results.crossAxis;
    const isTouch = inputMethod === 'touch';
    const idealMax = isTouch ? 8 : 2;
    const scoreDenom = isTouch ? 1.0 : 0.3;
    const s = Math.min(1, ca.meanCoupling / scoreDenom) * (ca.meanCoupling < idealMax ? 1 : 0.5);
    scores.crossAxis = { score: s, weight: W.crossAxis, label: 'Cross-Axis Coupling',
      detail: `Mean coupling: ${ca.meanCoupling.toFixed(3)}${isTouch ? ' [touch-adjusted]' : ''}` };
    weightedSum += s * W.crossAxis; totalWeight += W.crossAxis; validCount++;
  }

  // 6. Pulse Response Latency
  if (results.pulseResponse && results.pulseResponse.valid) {
    const pr = results.pulseResponse;
    const latScore = rangeScore(pr.latencyMean, ScoringConfig.humanLatencyRange[0], ScoringConfig.humanLatencyRange[1], 0.03);
    const varScore = rangeScore(pr.latencyStd, ScoringConfig.humanLatencySD[0], ScoringConfig.humanLatencySD[1], 0.08);
    const s = latScore * 0.6 + varScore * 0.4;
    const detected = pr.responses.filter(r => r.latency !== null).length;
    scores.pulseResponse = { score: s, weight: W.pulseResponse, label: 'Response Latency',
      detail: `Mean: ${pr.latencyMean.toFixed(0)}ms (σ=${pr.latencyStd.toFixed(0)}ms), ${detected}/${pr.responses.length} pulses detected` };
    weightedSum += s * W.pulseResponse; totalWeight += W.pulseResponse; validCount++;
  }

  // 7. Cognitive-Motor Interference
  if (results.cogInterference && results.cogInterference.valid) {
    const ci = results.cogInterference;
    const allEffects = ci.flashEffects.map(f => f.increase);
    const meanAllInterference = MathEngine.stats(allEffects).mean;
    const maxInterference = Math.max(...allEffects.map(f => Math.abs(f)));
    let s = Math.min(1, Math.max(0, meanAllInterference) / 0.12);
    s = Math.max(s, Math.min(1, maxInterference / 0.25));
    if (ci.attentionEffect > 0.02) s = Math.min(1, s + 0.2);
    if (ci.userAnswer !== null) {
      s = Math.min(1, s + 0.1);
      if (Math.abs(ci.userAnswer - ci.correctAnswer) <= 1) s = Math.min(1, s + 0.15);
    }
    scores.cogInterference = { score: s, weight: W.cogInterference, label: 'Cognitive-Motor Interference',
      detail: `Mean interference: ${(meanAllInterference * 100).toFixed(1)}%, Attention effect: ${(ci.attentionEffect * 100).toFixed(1)}%, Answer: ${ci.userAnswer}/${ci.correctAnswer}` };
    weightedSum += s * W.cogInterference; totalWeight += W.cogInterference; validCount++;
  }

  // 8. Minimum Jerk
  if (results.minJerk && results.minJerk.valid) {
    const s = Math.min(1, Math.max(0, results.minJerk.meanR2 / 0.6));
    scores.minJerk = { score: s, weight: W.minJerk, label: 'Minimum Jerk Trajectory',
      detail: `Mean R²: ${results.minJerk.meanR2.toFixed(3)} (≥0.6 = strong biological match)` };
    weightedSum += s * W.minJerk; totalWeight += W.minJerk; validCount++;
  }

  const overall = totalWeight > 0 ? weightedSum / totalWeight : 0;
  let verdict, verdictClass;
  if (overall >= ScoringConfig.humanThreshold) {
    verdict = 'BIOLOGICAL CONTROLLER DETECTED'; verdictClass = 'score-human';
  } else if (overall >= ScoringConfig.uncertainThreshold) {
    verdict = 'UNCERTAIN — INCONCLUSIVE SIGNALS'; verdictClass = 'score-uncertain';
  } else {
    verdict = 'NON-BIOLOGICAL CONTROLLER SUSPECTED'; verdictClass = 'score-bot';
  }

  return { overall, scores, validCount, verdict, verdictClass };
}


// ─── MAIN ANALYSIS ENTRY POINT ──────────────────────────────

/**
 * Run full CLNP analysis on raw data using challenge parameters.
 *
 * @param {Object} rawData - Client-submitted raw data
 *   @param {Array} rawData.pointer - [[t, x, y], ...]
 *   @param {Array} rawData.accel - [[t, ax, ay, az], ...] (optional)
 *   @param {Object} rawData.phases - { trackingStart, dualtaskStart, testEnd }
 *   @param {Object} rawData.canvas - { width, height }
 *   @param {string} rawData.inputMethod - 'mouse' | 'touch' | 'trackpad'
 *   @param {number|null} rawData.cogAnswer - User's cognitive task answer
 *
 * @param {Object} challenge - Server-stored challenge parameters
 *
 * @returns {Object} { overall, scores, verdict, verdictClass, validCount, sampleRate, sampleCount }
 */
function analyze(rawData, challenge) {
  // 1. Reconstruct tracking data from challenge params
  const tracking = reconstructTracking(rawData.pointer, rawData.phases, challenge, rawData.canvas);

  if (tracking.length < 50) {
    return { overall: 0, scores: {}, verdict: 'INSUFFICIENT DATA', verdictClass: 'score-bot', validCount: 0 };
  }

  // 2. Estimate sample rate
  const dts = [];
  for (let i = 1; i < Math.min(tracking.length, 500); i++) dts.push(tracking[i].t - tracking[i - 1].t);
  const sampleRate = dts.length > 0 ? 1000 / (dts.reduce((a, b) => a + b, 0) / dts.length) : 60;

  // 3. Extract probe frequencies from challenge for transfer function analysis
  const probeFreqs = challenge.perturbation.probes.map(p => p.freq);

  // 4. Run all 8 analyses
  const results = {};
  results.transferFn = analyzeTransferFunction(tracking, sampleRate, probeFreqs);
  results.tremor = analyzeTremor(tracking, sampleRate);
  results.accelTremor = analyzeAccelTremor(rawData.accel);
  results.oneOverF = analyze1fNoise(tracking, sampleRate);
  results.signalDepNoise = analyzeSignalDepNoise(tracking);
  results.crossAxis = analyzeCrossAxis(tracking, challenge.perturbation.pulses, rawData.phases.trackingStart);
  results.pulseResponse = analyzePulseResponses(tracking, challenge.perturbation.pulses, rawData.phases.trackingStart);
  results.cogInterference = analyzeCogInterference(tracking, challenge.cogTask.flashes, rawData.phases.dualtaskStart, rawData.cogAnswer);
  results.minJerk = analyzeMinJerk(results.pulseResponse);

  // 5. Score
  const scoreResult = scoreResults(results, rawData.inputMethod);

  return {
    ...scoreResult,
    sampleRate: Math.round(sampleRate),
    sampleCount: tracking.length,
    inputMethod: rawData.inputMethod,
  };
}

module.exports = { analyze };
