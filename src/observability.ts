import { pino, destination, type Logger } from "pino";
import { trace, SpanStatusCode, type Span } from "@opentelemetry/api";

/** Structured JSON logs. Tokens and secrets are redacted before anything is written. */
export function createLogger(level = process.env.LOG_LEVEL ?? "info", opts: { stderr?: boolean } = {}): Logger {
  return pino(
    {
      level,
      base: { service: "tenantdesk-mcp" },
      redact: { paths: ["req.headers.authorization", "headers.authorization", "token", "*.token"], censor: "[redacted]" },
    },
    // In stdio mode stdout carries the MCP protocol, so logs must go to stderr.
    destination(opts.stderr ? 2 : 1),
  );
}

export const tracer = trace.getTracer("tenantdesk-mcp");

/** Runs fn inside an OpenTelemetry span. A no-op unless telemetry was started. */
export async function withSpan<T>(name: string, attrs: Record<string, string | number>, fn: (span: Span) => Promise<T>): Promise<T> {
  return tracer.startActiveSpan(name, { attributes: attrs }, async (span) => {
    try {
      return await fn(span);
    } catch (err) {
      span.setStatus({ code: SpanStatusCode.ERROR });
      throw err;
    } finally {
      span.end();
    }
  });
}

/**
 * Starts OpenTelemetry tracing (OTLP over HTTP) when OTEL_EXPORTER_OTLP_ENDPOINT is set.
 * Loaded lazily so the SDK costs nothing when tracing is off.
 */
export async function startTelemetry(cfg: { OTEL_EXPORTER_OTLP_ENDPOINT?: string; OTEL_SERVICE_NAME: string }) {
  if (!cfg.OTEL_EXPORTER_OTLP_ENDPOINT) return undefined;
  const { NodeSDK } = await import("@opentelemetry/sdk-node");
  const { OTLPTraceExporter } = await import("@opentelemetry/exporter-trace-otlp-http");
  const sdk = new NodeSDK({
    serviceName: cfg.OTEL_SERVICE_NAME,
    traceExporter: new OTLPTraceExporter({ url: `${cfg.OTEL_EXPORTER_OTLP_ENDPOINT.replace(/\/$/, "")}/v1/traces` }),
  });
  sdk.start();
  return sdk;
}

/** Minimal Prometheus registry: counters and a latency histogram, served at /metrics. */
export class Metrics {
  private counters = new Map<string, { help: string; values: Map<string, number> }>();
  private histo = new Map<string, number[]>();
  private static BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500];

  inc(name: string, help: string, labels: Record<string, string> = {}) {
    const c = this.counters.get(name) ?? { help, values: new Map() };
    const key = Metrics.labels(labels);
    c.values.set(key, (c.values.get(key) ?? 0) + 1);
    this.counters.set(name, c);
  }

  observeMs(labels: Record<string, string>, ms: number) {
    const key = Metrics.labels(labels);
    const counts = this.histo.get(key) ?? new Array(Metrics.BUCKETS.length + 2).fill(0);
    Metrics.BUCKETS.forEach((b, i) => {
      if (ms <= b) counts[i]++;
    });
    counts[Metrics.BUCKETS.length]++; // count (+Inf)
    counts[Metrics.BUCKETS.length + 1] += ms; // sum
    this.histo.set(key, counts);
  }

  render(): string {
    const out: string[] = [];
    for (const [name, c] of this.counters) {
      out.push(`# HELP ${name} ${c.help}`, `# TYPE ${name} counter`);
      for (const [l, v] of c.values) out.push(`${name}${l} ${v}`);
    }
    const h = "tenantdesk_tool_duration_ms";
    out.push(`# HELP ${h} MCP tool call duration in milliseconds`, `# TYPE ${h} histogram`);
    for (const [l, counts] of this.histo) {
      const inner = l.slice(1, -1);
      const sep = inner ? "," : "";
      Metrics.BUCKETS.forEach((b, i) => out.push(`${h}_bucket{${inner}${sep}le="${b}"} ${counts[i]}`));
      out.push(`${h}_bucket{${inner}${sep}le="+Inf"} ${counts[Metrics.BUCKETS.length]}`);
      out.push(`${h}_count${l} ${counts[Metrics.BUCKETS.length]}`, `${h}_sum${l} ${counts[Metrics.BUCKETS.length + 1]}`);
    }
    return out.join("\n") + "\n";
  }

  private static labels(l: Record<string, string>) {
    const parts = Object.entries(l).map(([k, v]) => `${k}="${v.replace(/["\\\n]/g, "_")}"`);
    return parts.length ? `{${parts.join(",")}}` : "";
  }
}
