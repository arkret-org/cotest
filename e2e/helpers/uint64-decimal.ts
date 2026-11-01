// Spec decimal-integers.schema.json#/$defs/uint64_decimal. Keep JSON wire values as strings.
const UINT64_MAX = 18446744073709551615n;

export function uint64Decimal(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 20
      || /[^0-9]/.test(value) || (value.length > 1 && value.startsWith("0"))
      || BigInt(value) > UINT64_MAX) {
    throw new Error("Expected a canonical uint64 decimal string");
  }
  return value;
}

export function uint64Value(value: unknown): bigint {
  return BigInt(uint64Decimal(value));
}
