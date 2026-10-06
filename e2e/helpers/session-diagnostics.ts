type DiagnosticRow = { sequence: number; value: string };
type DiagnosticPriority = "normal" | "critical" | "phase";

class DiagnosticRing {
  private readonly rows: DiagnosticRow[] = [];
  private cursor = 0;
  private readonly capacity: number;

  constructor(capacity: number) {
    this.capacity = capacity;
  }

  push(row: DiagnosticRow): boolean {
    if (this.rows.length < this.capacity) {
      this.rows.push(row);
      return false;
    }
    this.rows[this.cursor] = row;
    this.cursor = (this.cursor + 1) % this.capacity;
    return true;
  }

  snapshot(): DiagnosticRow[] {
    return [...this.rows.slice(this.cursor), ...this.rows.slice(0, this.cursor)];
  }
}

export function sessionDiagnosticPriority(line: string): DiagnosticPriority {
  let row: { type?: unknown; text?: unknown };
  try {
    row = JSON.parse(line);
  } catch {
    return "normal";
  }
  if (!row || typeof row !== "object") return "normal";
  const text = typeof row.text === "string" ? row.text : "";
  if (text.includes("joint Sidecar preparation stage")) return "phase";
  if (["pageerror", "error", "warning", "http-error", "requestfailed"].includes(String(row.type)) ||
    /Sidecar access preparation will resume|Sidecar restore failed|owned Agent inventory read will resume|panicked at|RuntimeError/.test(text)) {
    return "critical";
  }
  return "normal";
}

export class SessionDiagnostics {
  private readonly head: DiagnosticRow[] = [];
  // Reserve independent shares so routine rendering cannot evict sparse failures or phases.
  private readonly tail = new DiagnosticRing(2999);
  private readonly critical = new DiagnosticRing(500);
  private readonly phases = new DiagnosticRing(500);
  private sequence = 0;
  private omitted = 0;

  push(line: string, priority: DiagnosticPriority = sessionDiagnosticPriority(line)): void {
    const value = line.length > 4000
      ? `${line.slice(0, 4000)}... [truncated]`
      : line;
    const row = { sequence: this.sequence++, value };
    if (this.head.length < 1000) {
      this.head.push(row);
    } else {
      const ring = priority === "phase" ? this.phases : priority === "critical" ? this.critical : this.tail;
      if (ring.push(row)) this.omitted += 1;
    }
  }

  lines(): string[] {
    const retained = [...this.tail.snapshot(), ...this.critical.snapshot(), ...this.phases.snapshot()]
      .sort((a, b) => a.sequence - b.sequence);
    const head = this.head.map((row) => row.value);
    if (this.omitted === 0) return [...head, ...retained.map((row) => row.value)];
    return [
      ...head,
      JSON.stringify({
        type: "diagnostic_truncated",
        retained_lines: this.head.length + retained.length,
        omitted_lines: this.omitted,
      }),
      ...retained.map((row) => row.value),
    ];
  }

  join(separator: string): string {
    return this.lines().join(separator);
  }
}
