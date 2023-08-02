export function isString(v: unknown): v is string {
  return typeof v === "string";
}
export function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(isString);
}
export function isStringOrStringArray(v: unknown): v is string | string[] {
  return Array.isArray(v) ? v.every(isString) : isString(v);
}
export function isNumber(v: unknown): v is number {
  return typeof v === "number";
}
export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function includesClaim<
  P extends Record<string, unknown>,
  K extends string,
  T,
>(
  payload: P,
  key: K,
  isValid: (value: unknown) => value is T,
): payload is P & { [Key in K]: T } {
  return (key in payload) && isValid(payload[key]);
}
export function optionallyIncludesClaim<
  P extends Record<string, unknown>,
  K extends string,
  T,
>(
  payload: P,
  key: K,
  isValid: (value: unknown) => value is T,
): payload is P & { [Key in K]?: T } {
  return !(key in payload) || isValid(payload[key]);
}
