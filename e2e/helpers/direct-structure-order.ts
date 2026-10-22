// Reuse the caller's SDK canonical key exactly once per row and per snapshot.
// Sorting retains the original rows, duplicates and stable order for equal keys.
export function orderByCanonicalKey<T>(rows: readonly T[], key: (row: T) => string): T[] {
  return rows.map(row => ({ row, key: key(row) }))
    .sort((a, b) => a.key.localeCompare(b.key))
    .map(item => item.row);
}
