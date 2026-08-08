// @types/express@5's ParamsDictionary types every route param as
// `string | string[]`, matching Express 5 now being able to capture a
// repeated parameter name (e.g. two `:id` segments in one pattern) as an
// array. Every single-`:id` route in this app uses the name exactly once,
// so it can never actually be an array here - but a blind `as string` cast
// would silently misbehave if that ever stopped being true. This throws
// clearly instead, the same fail-loud preference used elsewhere in this
// codebase (e.g. excludes fetch failure aborting a scan rather than
// running unfiltered).
export function singleParam(value: string | string[]): string {
  if (Array.isArray(value)) {
    throw new Error(`expected a single route param, got an array: ${JSON.stringify(value)}`);
  }
  return value;
}
