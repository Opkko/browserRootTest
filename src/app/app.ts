import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';

type CheckResult = {
  name: string;
  pass: boolean;
  weight: number;
  details?: any;
};

@Component({
  selector: 'app-root',
  imports: [CommonModule],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App implements OnInit {
  results: CheckResult[] = [];
  riskScore = 0;
  summary = '';
  environment = {
    userAgent: '',
    platform: '',
    language: '',
    hardwareConcurrency: 0,
  };

  ngOnInit() {
    this.runAll();
  }

  async runAll() {
    this.environment = {
      userAgent: navigator.userAgent ?? '',
      platform: (navigator as any).platform ?? '',
      language: navigator.language ?? '',
      hardwareConcurrency: navigator.hardwareConcurrency ?? 0,
    };

    const checks: CheckResult[] = [];

    checks.push(...this.nativeIntegrityChecks());
    checks.push(...this.descriptorChecks());
    checks.push(this.globalPollutionCheck());
    checks.push(this.timingJitterCheck());
    checks.push(await this.iframeConsistencyCheck());
    checks.push(await this.workerConsistencyCheck());

    this.results = checks;
    this.riskScore = this.computeRiskScore(checks);
    this.summary = this.makeSummary(this.riskScore, checks);
  }

  private isNative(fn: any): boolean {
    try {
      const s = Function.prototype.toString.call(fn);
      return typeof s === 'string' && s.includes('[native code]');
    } catch {
      return false;
    }
  }

  private nativeIntegrityChecks(): CheckResult[] {
    const targets: Array<{ name: string; fn: any; weight: number }> = [
      { name: 'window.alert looks native', fn: (window as any).alert, weight: 8 },
      { name: 'window.setTimeout looks native', fn: window.setTimeout, weight: 10 },
      { name: 'window.fetch looks native', fn: (window as any).fetch, weight: 10 },
      { name: 'console.log looks native', fn: console.log, weight: 6 },
      { name: 'Function.prototype.toString looks native', fn: Function.prototype.toString, weight: 14 },
    ];

    return targets.map((t) => {
      const pass = this.isNative(t.fn);
      return {
        name: t.name,
        pass,
        weight: t.weight,
        details: pass ? undefined : this.safeToString(t.fn),
      };
    });
  }

  private descriptorChecks(): CheckResult[] {
    const checks: CheckResult[] = [];

    try {
      const d = Object.getOwnPropertyDescriptor(Function.prototype, 'toString');
      const pass = !!d && typeof d.value === 'function';
      checks.push({
        name: 'Descriptor: Function.prototype.toString exists',
        pass,
        weight: 10,
        details: d ?? 'missing',
      });
    } catch (e) {
      checks.push({
        name: 'Descriptor: Function.prototype.toString readable',
        pass: false,
        weight: 10,
        details: String(e),
      });
    }

    try {
      const hasFetch = typeof (window as any).fetch === 'function';
      const d2 = Object.getOwnPropertyDescriptor(window as any, 'fetch');
      checks.push({
        name: 'Presence: window.fetch exists',
        pass: hasFetch,
        weight: 4,
        details: d2 ?? 'n/a',
      });
    } catch (e) {
      checks.push({ name: 'Presence: window.fetch check', pass: false, weight: 4, details: String(e) });
    }

    try {
      const d3 = Object.getOwnPropertyDescriptor(Object, 'defineProperty');
      const pass = !!d3 && typeof d3.value === 'function' && this.isNative(d3.value);
      checks.push({
        name: 'Integrity: Object.defineProperty looks native',
        pass,
        weight: 8,
        details: d3 ?? 'missing',
      });
    } catch (e) {
      checks.push({
        name: 'Integrity: Object.defineProperty readable',
        pass: false,
        weight: 8,
        details: String(e),
      });
    }

    return checks;
  }

  private globalPollutionCheck(): CheckResult {
    const keywords = ['frida', 'xposed', 'substrate', 'magisk', 'hook', 'lsposed'];
    const props = Object.getOwnPropertyNames(window as any);
    const hits = props.filter((p) => keywords.some((k) => p.toLowerCase().includes(k)));

    const pass = hits.length === 0;
    return {
      name: 'Global pollution: suspicious window properties',
      pass,
      weight: 8,
      details: hits.slice(0, 30),
    };
  }

  private timingJitterCheck(): CheckResult {
    const samples = 120;
    const durations: number[] = [];

    try {
      for (let i = 0; i < samples; i++) {
        const start = performance.now();
        let x = 0;
        for (let j = 0; j < 6000; j++) x += (j ^ i) & 7;
        const end = performance.now();
        durations.push(end - start + (x === 123456 ? 0 : 0));
      }

      const med = this.median(durations);
      const mad = this.median(durations.map((d) => Math.abs(d - med)));

      const pass = Number.isFinite(med) && Number.isFinite(mad) && med > 0 && mad / med < 0.35;

      return {
        name: 'Timing jitter: micro-benchmark variability',
        pass,
        weight: 10,
        details: {
          medianMs: this.round(med, 4),
          madMs: this.round(mad, 4),
          ratio: this.round(mad / (med || 1), 4),
          samples,
        },
      };
    } catch (e) {
      return { name: 'Timing jitter: runnable', pass: false, weight: 10, details: String(e) };
    }
  }

  private async iframeConsistencyCheck(): Promise<CheckResult> {
    try {
      const iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      iframe.srcdoc = '<!doctype html><html><head></head><body></body></html>';
      document.body.appendChild(iframe);

      await new Promise<void>((resolve) => {
        const done = () => resolve();
        iframe.addEventListener('load', done, { once: true });
        setTimeout(done, 250);
      });

      const w = iframe.contentWindow as any;
      if (!w) {
        iframe.remove();
        return { name: 'Consistency: iframe accessible', pass: false, weight: 10, details: 'no contentWindow' };
      }

      const parentToString = Function.prototype.toString.call(window.setTimeout);
      const frameToString = w.Function.prototype.toString.call(w.setTimeout);

      const sameNativeSignal =
        typeof parentToString === 'string' &&
        typeof frameToString === 'string' &&
        parentToString.includes('[native code]') === frameToString.includes('[native code]');

      const parentDesc = Object.getOwnPropertyDescriptor(Function.prototype, 'toString');
      const frameDesc = w.Object.getOwnPropertyDescriptor(w.Function.prototype, 'toString');

      const descriptorShapeOk =
        !!parentDesc &&
        !!frameDesc &&
        typeof parentDesc.value === 'function' &&
        typeof frameDesc.value === 'function';

      iframe.remove();

      const pass = sameNativeSignal && descriptorShapeOk;

      return {
        name: 'Consistency: main window vs iframe',
        pass,
        weight: 12,
        details: {
          sameNativeSignal,
          descriptorShapeOk,
        },
      };
    } catch (e) {
      return { name: 'Consistency: main window vs iframe', pass: false, weight: 12, details: String(e) };
    }
  }

  private async workerConsistencyCheck(): Promise<CheckResult> {
    if (typeof Worker === 'undefined') {
      return { name: 'Consistency: web worker available', pass: false, weight: 8, details: 'Worker unsupported' };
    }

    const code = `
      self.onmessage = () => {
        try {
          const fn = () => {};
          const toStringNative = Function.prototype.toString.toString().includes('[native code]');
          const fnString = Function.prototype.toString.call(fn);
          const payload = {
            ok: true,
            toStringNative,
            fnStringHasNative: fnString.includes('[native code]'),
            userAgent: (self.navigator && self.navigator.userAgent) ? self.navigator.userAgent : ''
          };
          self.postMessage(payload);
        } catch (e) {
          self.postMessage({ ok: false, error: String(e) });
        }
      };
    `;

    let url: string | undefined;
    try {
      const blob = new Blob([code], { type: 'text/javascript' });
      url = URL.createObjectURL(blob);
      const worker = new Worker(url);

      const result = await new Promise<any>((resolve) => {
        const timer = setTimeout(() => resolve({ ok: false, error: 'timeout' }), 600);
        worker.onmessage = (ev) => {
          clearTimeout(timer);
          resolve((ev as MessageEvent).data);
        };
        worker.onerror = (ev: any) => {
          clearTimeout(timer);
          resolve({ ok: false, error: String(ev?.message ?? ev) });
        };
        worker.postMessage({});
      });

      worker.terminate();
      URL.revokeObjectURL(url);

      const pass = result?.ok === true && result.toStringNative === true;

      return {
        name: 'Consistency: worker baseline sanity',
        pass,
        weight: 8,
        details: result,
      };
    } catch (e) {
      if (url) URL.revokeObjectURL(url);
      return { name: 'Consistency: worker baseline sanity', pass: false, weight: 8, details: String(e) };
    }
  }

  private computeRiskScore(checks: CheckResult[]): number {
    const total = checks.reduce((sum, c) => sum + (Number.isFinite(c.weight) ? c.weight : 0), 0);
    const failed = checks.reduce((sum, c) => sum + (!c.pass ? c.weight : 0), 0);
    if (total <= 0) return 0;
    return Math.max(0, Math.min(100, Math.round((failed / total) * 100)));
  }

  private makeSummary(score: number, checks: CheckResult[]): string {
    const failed = checks.filter((c) => !c.pass).length;
    const total = checks.length;

    if (score < 20) return `Low tampering likelihood (${score}/100). Failed ${failed}/${total}.`;
    if (score < 50) return `Moderate tampering likelihood (${score}/100). Failed ${failed}/${total}.`;
    if (score < 75) return `High tampering likelihood (${score}/100). Failed ${failed}/${total}.`;
    return `Very high tampering likelihood (${score}/100). Failed ${failed}/${total}.`;
  }

  private median(values: number[]): number {
    const v = values.slice().sort((a, b) => a - b);
    const mid = Math.floor(v.length / 2);
    if (v.length === 0) return NaN;
    return v.length % 2 === 0 ? (v[mid - 1] + v[mid]) / 2 : v[mid];
  }

  private round(x: number, digits: number): number {
    const p = Math.pow(10, digits);
    return Math.round(x * p) / p;
  }

  private safeToString(v: any): string {
    try {
      return String(v);
    } catch {
      return '[unstringifiable]';
    }
  }

  trackByName(_: number, r: CheckResult) {
    return r.name;
  }
}
