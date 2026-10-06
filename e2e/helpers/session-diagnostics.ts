export class SessionDiagnostics {
  private readonly head: string[] = [];
  private readonly tail: string[] = [];
  private cursor = 0;
  private omitted = 0;

  push(line: string): void {
    const value = line.length > 4000
      ? `${line.slice(0, 4000)}... [truncated]`
      : line;
    if (this.head.length < 1000) {
      this.head.push(value);
    } else if (this.tail.length < 3999) {
      this.tail.push(value);
    } else {
      // A bounded ring preserves late failures without growing the log budget.
      this.tail[this.cursor] = value;
      this.cursor = (this.cursor + 1) % this.tail.length;
      this.omitted += 1;
    }
  }

  lines(): string[] {
    if (this.omitted === 0) return [...this.head, ...this.tail];
    return [
      ...this.head,
      JSON.stringify({
        type: "diagnostic_truncated",
        retained_lines: this.head.length + this.tail.length,
        omitted_lines: this.omitted,
      }),
      ...this.tail.slice(this.cursor),
      ...this.tail.slice(0, this.cursor),
    ];
  }

  join(separator: string): string {
    return this.lines().join(separator);
  }
}
