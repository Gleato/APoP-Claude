/**
 * CLNP Embedded Liveness Detection — Client Library
 *
 * AGENT COOKIE CRUMB: This is the zero-friction, invisible version of CLNP.
 * Instead of a dedicated "follow the dot" test, this library:
 *   1. Applies sub-perceptual CSS transform perturbations (1-2px sine waves,
 *      3-5px pulses) to interactive elements during hover
 *   2. Captures the user's pointer response at 60Hz+
 *   3. Optionally captures accelerometer data on mobile
 *   4. Submits raw data to the server for biomechanical analysis (7 metrics)
 *
 * The perturbation signal lives in CUMULATIVE HOVER TIME — not wall-clock time.
 * When the user hovers element A for 2s, leaves, hovers element B for 3s,
 * the perturbation is continuous at t=0→5s. This preserves FFT coherence
 * for the transfer function analysis.
 *
 * CSS transforms (translate) are compositing-only — no reflow, no layout shift,
 * doesn't affect hit-test regions. The element visually shifts 1-2px but clicks
 * still register at the original position.
 *
 * Usage:
 *   const clnp = new CLNPEmbed({ serverUrl: '' });
 *   clnp.observe('.btn, a, input, [data-clnp]');
 *   await clnp.start();
 *
 *   // Later, when you need a verdict:
 *   const result = await clnp.getResult();
 *   // result.verdict, result.overall, result.receipt
 *
 * Zero dependencies. No build step. ~400 lines.
 */

"use strict";

class CLNPEmbed {
  /**
   * @param {Object} opts
   * @param {string} opts.serverUrl - Base URL for CLNP server (default: same origin)
   */
  constructor(opts = {}) {
    this._serverUrl = opts.serverUrl || '';

    // State
    this._started = false;
    this._destroyed = false;
    this._token = null;
    this._challenge = null;

    // Observation
    this._selectors = [];
    this._observedElements = new Set();
    this._mutationObserver = null;

    // Hover tracking
    this._hoveredEl = null;        // Currently hovered observed element
    this._hoveredIndex = -1;       // Index of currently hovered element
    this._hoverStartWall = 0;      // Wall time when current hover started
    this._cumulativeHoverTime = 0; // Total ms spent hovering observed elements
    this._lastHoverTick = 0;       // Last rAF timestamp for hover time accumulation

    // Perturbation state
    this._rafId = null;
    this._nextPulseIndex = 0;      // Next pulse to fire from challenge schedule

    // Data collection
    this._pointer = [];            // [[wallTime, hoverTime, x, y, elementIndex], ...]
    this._accel = [];              // [[wallTime, ax, ay, az], ...]
    this._hovers = [];             // [[elemIdx, startWall, endWall, startHover, endHover], ...]
    this._pulseLog = [];           // [[hoverTime, wallTime, dx, dy, elementIndex], ...]
    this._elementRects = new Map(); // elementIndex -> { x, y, w, h }

    // Element index mapping
    this._elementIndexMap = new Map(); // DOM element -> integer index
    this._nextElementIndex = 0;

    // Device detection: determines interaction model + server-side scoring profile.
    // Three categories: 'touch' (phone/tablet), 'trackpad' (laptop), 'mouse' (desktop).
    // Touch has no hover — finger contact = interaction. Trackpad and mouse have hover
    // but differ in tremor characteristics. Detection uses multiple signals.
    this._isTouch = false;
    this._deviceType = 'mouse';    // 'mouse' | 'trackpad' | 'touch'
    this._touchActive = false;     // Is a finger currently down?
    this._touchElementIndex = -1;  // Which observed element is being touched?
    this._pointerTypes = {};       // Count of observed pointerType values

    // Bound handlers
    this._onPointerMove = this._handlePointerMove.bind(this);
    this._onPointerEnter = this._handlePointerEnter.bind(this);
    this._onPointerLeave = this._handlePointerLeave.bind(this);
    this._onTouchStart = this._handleTouchStart.bind(this);
    this._onTouchMove = this._handleTouchMove.bind(this);
    this._onTouchEnd = this._handleTouchEnd.bind(this);
    this._tick = this._perturbTick.bind(this);

    // Accelerometer
    this._accelListening = false;
    this._onDeviceMotion = this._handleDeviceMotion.bind(this);
  }


  // ─── PUBLIC API ──────────────────────────────────────────────

  /**
   * Register CSS selectors for elements to observe and perturb.
   * Can be called multiple times before or after start().
   * @param {string} selector - CSS selector string
   */
  observe(selector) {
    this._selectors.push(selector);
    if (this._started) this._scanElements();
  }

  /**
   * Fetch a challenge from the server and begin observation.
   * Starts the rAF perturbation loop and pointer capture.
   */
  async start() {
    if (this._started || this._destroyed) return;
    this._started = true;

    // Fetch embed challenge
    const res = await fetch(this._serverUrl + '/api/embed/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    if (!res.ok) throw new Error(`Embed challenge failed: ${res.status}`);
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Challenge failed');

    this._token = data.token;
    this._challenge = data.challenge;

    // Scan for observed elements
    this._scanElements();

    // Start MutationObserver to detect dynamically added elements
    this._mutationObserver = new MutationObserver(() => this._scanElements());
    this._mutationObserver.observe(document.body, { childList: true, subtree: true });

    // Detect device type from hardware signals
    this._isTouch = ('ontouchstart' in window) && navigator.maxTouchPoints > 0;
    this._deviceType = this._detectDeviceType();

    if (this._isTouch) {
      // Touch mode: capture touchstart/move/end globally.
      // Touch contact = hover equivalent. We accumulate hover time while
      // a finger is down and moving near/on an observed element.
      document.addEventListener('touchstart', this._onTouchStart, { passive: true });
      document.addEventListener('touchmove', this._onTouchMove, { passive: true });
      document.addEventListener('touchend', this._onTouchEnd, { passive: true });
      document.addEventListener('touchcancel', this._onTouchEnd, { passive: true });
    } else {
      // Desktop: pointer hover mode
      document.addEventListener('pointermove', this._onPointerMove, { passive: true });
    }

    // Start perturbation loop
    this._rafId = requestAnimationFrame(this._tick);

    // Request accelerometer on mobile
    this._requestAccel();
  }

  /**
   * Check if enough data has been collected for a verdict.
   * Readiness thresholds:
   *   - 8s cumulative hover time
   *   - 500+ pointer samples
   *   - 2+ pulses delivered
   *   - 2+ distinct elements interacted with
   */
  isReady() {
    if (!this._started || !this._challenge) return false;
    const pulsesDelivered = this._pulseLog.length;
    const uniqueElements = new Set(this._pointer.map(p => p[4])).size;

    // Touch interactions are shorter but more deliberate — lower thresholds.
    // Desktop hover accumulates passively; touch requires active finger contact.
    const minHover = this._isTouch ? 4000 : 8000;
    const minSamples = this._isTouch ? 200 : 500;
    const minPulses = this._isTouch ? 2 : 2;
    const minElements = this._isTouch ? 1 : 2;

    return (
      this._cumulativeHoverTime >= minHover &&
      this._pointer.length >= minSamples &&
      pulsesDelivered >= minPulses &&
      uniqueElements >= minElements
    );
  }

  /**
   * Submit collected data to the server and return the verdict.
   * If not ready, waits up to 30s for enough data (polls every 500ms).
   * @param {number} [timeoutMs=30000] - Max wait time for readiness
   * @returns {Promise<Object>} Server verdict { ok, verdict, overall, receipt, scores, ... }
   */
  async getResult(timeoutMs = 30000) {
    if (!this._started) throw new Error('CLNPEmbed not started');
    if (this._destroyed) throw new Error('CLNPEmbed destroyed');

    // Wait for readiness
    const deadline = Date.now() + timeoutMs;
    while (!this.isReady() && Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 500));
    }

    // Build and submit payload
    const payload = this._buildPayload();
    const res = await fetch(this._serverUrl + '/api/embed/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Embed verify failed: ${res.status}`);
    const data = await res.json();

    // Auto-destroy after verdict
    this.destroy();
    return data;
  }

  /**
   * Clean up: remove listeners, restore CSS transforms, stop rAF loop.
   */
  destroy() {
    if (this._destroyed) return;
    this._destroyed = true;
    this._started = false;

    // Stop rAF
    if (this._rafId) cancelAnimationFrame(this._rafId);

    // Remove listeners
    document.removeEventListener('pointermove', this._onPointerMove);
    document.removeEventListener('touchstart', this._onTouchStart);
    document.removeEventListener('touchmove', this._onTouchMove);
    document.removeEventListener('touchend', this._onTouchEnd);
    document.removeEventListener('touchcancel', this._onTouchEnd);
    if (this._accelListening) {
      window.removeEventListener('devicemotion', this._onDeviceMotion);
    }
    if (this._mutationObserver) {
      this._mutationObserver.disconnect();
    }

    // Remove hover listeners from all observed elements
    for (const el of this._observedElements) {
      el.removeEventListener('pointerenter', this._onPointerEnter);
      el.removeEventListener('pointerleave', this._onPointerLeave);
      el.style.transform = ''; // Restore original transform
    }

    // End any active hover
    if (this._hoveredEl) this._endHover();
  }

  /**
   * Get current collection stats (for debug panels).
   */
  getStats() {
    return {
      hoverTime: Math.round(this._cumulativeHoverTime),
      pointerSamples: this._pointer.length,
      pulsesDelivered: this._pulseLog.length,
      uniqueElements: new Set(this._pointer.map(p => p[4])).size,
      isReady: this.isReady(),
      isHovering: this._hoveredEl !== null,
      observedElements: this._observedElements.size,
      deviceType: this._deviceType,
    };
  }


  // ─── INTERNAL: ELEMENT MANAGEMENT ────────────────────────────

  /**
   * Scan DOM for elements matching registered selectors.
   * Idempotent — only adds new elements, doesn't duplicate listeners.
   */
  _scanElements() {
    for (const selector of this._selectors) {
      const els = document.querySelectorAll(selector);
      for (const el of els) {
        if (this._observedElements.has(el)) continue;
        this._observedElements.add(el);

        // Assign stable integer index
        const idx = this._nextElementIndex++;
        this._elementIndexMap.set(el, idx);

        // Listen for hover
        el.addEventListener('pointerenter', this._onPointerEnter, { passive: true });
        el.addEventListener('pointerleave', this._onPointerLeave, { passive: true });
      }
    }
  }


  // ─── INTERNAL: HOVER TRACKING ────────────────────────────────

  _handlePointerEnter(e) {
    const el = e.currentTarget;
    if (!this._observedElements.has(el)) return;

    // End previous hover if any (shouldn't happen, but safety)
    if (this._hoveredEl) this._endHover();

    this._hoveredEl = el;
    this._hoveredIndex = this._elementIndexMap.get(el);
    this._hoverStartWall = performance.now();
    this._hoverStartCumulTime = this._cumulativeHoverTime; // Snapshot for hover log
    this._lastHoverTick = this._hoverStartWall;

    // Capture element rect at hover start
    const rect = el.getBoundingClientRect();
    this._elementRects.set(this._hoveredIndex, {
      x: rect.left, y: rect.top, w: rect.width, h: rect.height,
    });
  }

  _handlePointerLeave(e) {
    const el = e.currentTarget;
    if (el !== this._hoveredEl) return;
    this._endHover();
  }

  _endHover() {
    if (!this._hoveredEl) return;

    const now = performance.now();

    // Add final delta since last tick (don't re-add the full duration —
    // cumulative time was already accumulated incrementally by rAF + pointermove)
    if (this._lastHoverTick > 0) {
      this._cumulativeHoverTime += (now - this._lastHoverTick);
    }
    this._lastHoverTick = 0;

    // Record hover period
    this._hovers.push([
      this._hoveredIndex,
      this._hoverStartWall,
      now,
      this._hoverStartCumulTime,
      this._cumulativeHoverTime,
    ]);

    // Clear CSS transform
    this._hoveredEl.style.transform = '';

    this._hoveredEl = null;
    this._hoveredIndex = -1;
  }


  // ─── INTERNAL: POINTER CAPTURE ───────────────────────────────

  _handlePointerMove(e) {
    // Only capture during hover on observed elements
    if (!this._hoveredEl || this._hoveredIndex < 0) return;

    const now = performance.now();

    // Update cumulative hover time
    if (this._lastHoverTick > 0) {
      this._cumulativeHoverTime += (now - this._lastHoverTick);
    }
    this._lastHoverTick = now;

    // Record pointer sample: [wallTime, hoverTime, x, y, elementIndex]
    this._pointer.push([
      now,
      this._cumulativeHoverTime,
      e.clientX,
      e.clientY,
      this._hoveredIndex,
    ]);
  }


  // ─── INTERNAL: TOUCH HANDLERS ──────────────────────────────
  // AGENT COOKIE CRUMB: On touch devices there is no "hover". Instead:
  //   - touchstart: finger down → find nearest observed element via elementFromPoint
  //   - touchmove: finger dragging → accumulate hover time + capture samples
  //   - touchend: finger up → end the "hover" period
  // We also capture ANY scroll-related touch movement (even when not on an
  // observed element) to get passive tremor + noise data. In that case we
  // attribute samples to the nearest element and still accumulate hover time,
  // since the finger is physically touching the screen.

  _handleTouchStart(e) {
    if (!e.touches.length) return;
    const touch = e.touches[0];
    this._touchActive = true;

    // Find which observed element is under the finger
    const el = this._findObservedElement(touch.clientX, touch.clientY);
    if (el) {
      this._startTouchHover(el);
    } else {
      // Finger is not on an observed element, but we still want data.
      // Find the nearest observed element and attribute to it.
      const nearest = this._findNearestObservedElement(touch.clientX, touch.clientY);
      if (nearest) this._startTouchHover(nearest);
    }
  }

  _handleTouchMove(e) {
    if (!this._touchActive || !e.touches.length) return;
    const touch = e.touches[0];
    const now = performance.now();

    // If we don't have a hover target yet, try to find one
    if (!this._hoveredEl) {
      const el = this._findObservedElement(touch.clientX, touch.clientY) ||
                 this._findNearestObservedElement(touch.clientX, touch.clientY);
      if (el) this._startTouchHover(el);
      if (!this._hoveredEl) return;
    }

    // Check if finger moved to a different observed element
    const elUnderFinger = this._findObservedElement(touch.clientX, touch.clientY);
    if (elUnderFinger && elUnderFinger !== this._hoveredEl && this._observedElements.has(elUnderFinger)) {
      this._endHover();
      this._startTouchHover(elUnderFinger);
    }

    // Accumulate hover time
    if (this._lastHoverTick > 0) {
      this._cumulativeHoverTime += (now - this._lastHoverTick);
    }
    this._lastHoverTick = now;

    // Record pointer sample
    this._pointer.push([
      now,
      this._cumulativeHoverTime,
      touch.clientX,
      touch.clientY,
      this._hoveredIndex,
    ]);
  }

  _handleTouchEnd(_e) {
    this._touchActive = false;
    if (this._hoveredEl) this._endHover();
  }

  /**
   * Find observed element directly under a point (exact hit test).
   */
  _findObservedElement(x, y) {
    const el = document.elementFromPoint(x, y);
    if (!el) return null;
    // Check the element itself and its ancestors
    let node = el;
    while (node && node !== document.body) {
      if (this._observedElements.has(node)) return node;
      node = node.parentElement;
    }
    return null;
  }

  /**
   * Find the nearest observed element to a point (for touch events
   * that land between elements — finger is on screen but not precisely on a button).
   */
  _findNearestObservedElement(x, y) {
    let nearest = null;
    let minDist = Infinity;
    for (const el of this._observedElements) {
      const rect = el.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      const dist = Math.sqrt((x - cx) ** 2 + (y - cy) ** 2);
      if (dist < minDist && dist < 300) { // Max 300px proximity
        minDist = dist;
        nearest = el;
      }
    }
    return nearest;
  }

  /**
   * Begin a touch "hover" on an observed element.
   */
  _startTouchHover(el) {
    if (this._hoveredEl) this._endHover();
    this._hoveredEl = el;
    this._hoveredIndex = this._elementIndexMap.get(el);
    this._hoverStartWall = performance.now();
    this._hoverStartCumulTime = this._cumulativeHoverTime;
    this._lastHoverTick = this._hoverStartWall;

    const rect = el.getBoundingClientRect();
    this._elementRects.set(this._hoveredIndex, {
      x: rect.left, y: rect.top, w: rect.width, h: rect.height,
    });
  }


  // ─── INTERNAL: PERTURBATION ENGINE ───────────────────────────

  /**
   * rAF loop: compute perturbation at current hover time, apply CSS transform.
   * Only active when hovering an observed element.
   */
  _perturbTick(timestamp) {
    if (this._destroyed) return;

    if (this._hoveredEl && this._challenge) {
      // Update cumulative hover time
      if (this._lastHoverTick > 0) {
        this._cumulativeHoverTime += (timestamp - this._lastHoverTick);
      }
      this._lastHoverTick = timestamp;

      const hoverT = this._cumulativeHoverTime;

      // Check if any pending pulse should fire
      this._checkPulses(hoverT, timestamp);

      // Compute perturbation
      const { x, y } = this._computePerturbation(hoverT);

      // Apply CSS transform
      this._hoveredEl.style.transform = `translate(${x.toFixed(2)}px, ${y.toFixed(2)}px)`;
    }

    this._rafId = requestAnimationFrame(this._tick);
  }

  /**
   * Compute multi-sine + pulse perturbation at cumulative hover time.
   * Mirrors server-side computeEmbedPerturbation exactly.
   */
  _computePerturbation(hoverT) {
    const pert = this._challenge.perturbation;
    let px = 0, py = 0;

    // Multi-sine component
    const elapsed = hoverT / 1000;
    for (const probe of pert.probes) {
      const phase = 2 * Math.PI * probe.freq * elapsed;
      px += probe.ampX * Math.sin(phase);
      py += probe.ampY * Math.sin(phase + probe.phaseOffset);
    }

    // Pulse component — check all pulses that have already been delivered
    for (const pulse of pert.pulses) {
      if (hoverT < pulse.hoverTimeMs) continue;
      const dt = hoverT - pulse.hoverTimeMs;
      if (dt < pert.pulseHoldDuration) {
        px += pulse.ampX;
        py += pulse.ampY;
      } else if (dt < pert.pulseHoldDuration + pert.pulseReturnDuration) {
        const frac = (dt - pert.pulseHoldDuration) / pert.pulseReturnDuration;
        const ease = 1 - frac * frac;
        px += pulse.ampX * ease;
        py += pulse.ampY * ease;
      }
    }

    return { x: px, y: py };
  }

  /**
   * Check if any new pulse should fire at the current hover time.
   * Log pulse deliveries for server verification.
   */
  _checkPulses(hoverT, wallTime) {
    const pulses = this._challenge.perturbation.pulses;
    while (this._nextPulseIndex < pulses.length) {
      const pulse = pulses[this._nextPulseIndex];
      if (hoverT >= pulse.hoverTimeMs) {
        // Pulse just fired — log it
        this._pulseLog.push([
          pulse.hoverTimeMs,
          wallTime,
          pulse.ampX,
          pulse.ampY,
          this._hoveredIndex,
        ]);
        this._nextPulseIndex++;
      } else {
        break;
      }
    }
  }


  // ─── INTERNAL: ACCELEROMETER ─────────────────────────────────

  _requestAccel() {
    // DeviceMotion for mobile tremor detection
    if (typeof DeviceMotionEvent === 'undefined') return;

    // iOS 13+ requires permission via user gesture
    if (typeof DeviceMotionEvent.requestPermission === 'function') {
      // We can't request permission without a user gesture.
      // Listen for any click/touchstart and request then.
      const handler = async () => {
        try {
          const perm = await DeviceMotionEvent.requestPermission();
          if (perm === 'granted') this._startAccel();
        } catch (_e) { /* Permission denied or error — silent fail */ }
        document.removeEventListener('click', handler);
        document.removeEventListener('touchstart', handler);
      };
      document.addEventListener('click', handler, { once: true, passive: true });
      document.addEventListener('touchstart', handler, { once: true, passive: true });
    } else {
      // Android / desktop — just start
      this._startAccel();
    }
  }

  _startAccel() {
    if (this._accelListening || this._destroyed) return;
    this._accelListening = true;
    window.addEventListener('devicemotion', this._onDeviceMotion, { passive: true });
  }

  _handleDeviceMotion(e) {
    const a = e.accelerationIncludingGravity;
    if (!a) return;
    this._accel.push([
      performance.now(),
      a.x || 0,
      a.y || 0,
      a.z || 0,
    ]);
  }


  // ─── INTERNAL: PAYLOAD ───────────────────────────────────────

  /**
   * Build compact payload for server submission.
   */
  _buildPayload() {
    // End current hover if active (ensures final hover period is recorded)
    if (this._hoveredEl) this._endHover();

    // Collect element rects
    const elements = [];
    for (const [idx, rect] of this._elementRects) {
      elements.push({ index: idx, rect });
    }

    return {
      token: this._token,
      pointer: this._pointer,
      accel: this._accel,
      hovers: this._hovers,
      pulseLog: this._pulseLog,
      elements,
      inputMethod: this._detectInputMethod(),
      deviceProfile: {
        type: this._deviceType,
        screenWidth: screen.width,
        screenHeight: screen.height,
        dpr: window.devicePixelRatio || 1,
        maxTouchPoints: navigator.maxTouchPoints || 0,
        hasAccel: this._accelListening,
      },
      viewportSize: {
        width: window.innerWidth,
        height: window.innerHeight,
      },
    };
  }

  /**
   * Detect device type from hardware signals.
   * AGENT COOKIE CRUMB: Three device categories affect scoring:
   *   - 'touch': Phone/tablet. No hover, finger contact = interaction.
   *              Min-jerk doesn't work (finger stays put, element moves under it).
   *              Tremor mainly from accelerometer. Cross-axis has larger coupling.
   *   - 'trackpad': Laptop. Has hover but trackpad produces different tremor
   *              than mouse (no wrist pivot, finger-on-surface). All metrics work.
   *   - 'mouse': Desktop. Full hover, all metrics optimal. Wrist pivot tremor.
   * Detection uses: touch capability, screen size, pixel ratio, platform hints.
   */
  _detectDeviceType() {
    const hasTouch = ('ontouchstart' in window) && navigator.maxTouchPoints > 0;
    const ua = navigator.userAgent || '';
    const platform = navigator.platform || '';
    const screenW = screen.width;
    const dpr = window.devicePixelRatio || 1;

    // Mobile/tablet: touch + small screen or mobile UA
    const mobileUA = /iPhone|iPad|iPod|Android|webOS|BlackBerry|IEMobile/i.test(ua);
    if (hasTouch && (mobileUA || screenW < 768)) {
      return 'touch';
    }

    // Laptop detection: macOS trackpad or smaller screen with touch
    // MacBooks always have trackpad as primary input
    const isMac = /Mac/i.test(platform);
    if (isMac && screenW < 2000) {
      return 'trackpad';
    }

    // Windows laptop heuristic: has touch (touchscreen laptop) but not mobile
    if (hasTouch && !mobileUA && screenW >= 768) {
      return 'trackpad';
    }

    return 'mouse';
  }

  /**
   * Get the input method string for the server payload.
   */
  _detectInputMethod() {
    return this._deviceType;
  }
}

// Export for both module and script-tag usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CLNPEmbed;
}
