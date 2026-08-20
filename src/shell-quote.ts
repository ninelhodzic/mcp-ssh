/**
 * POSIX shell quoting helpers.
 *
 * Remote commands in this server are built by string interpolation and run
 * through `sh -c` on the remote host (node-ssh execCommand). Any
 * caller-supplied value (paths, image names, env values, ...) MUST be routed
 * through `shellQuote` before interpolation; otherwise `$(...)`, backticks,
 * `"`, `$VAR`, `;` etc. embedded in the value execute or expand remotely.
 */

/**
 * Quote a string so a POSIX shell treats it as a single literal word.
 *
 * Wraps the value in single quotes; embedded single quotes are escaped as
 * `'\''` (close quote, literal quote, reopen quote). Inside single quotes a
 * POSIX shell performs no expansion of any kind, so the result is inert for
 * every metacharacter including `$()`, backticks, `$VAR`, `"`, spaces and
 * newlines. An empty string quotes to `''` (still one empty word).
 */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * True if `name` is a valid POSIX environment-variable / shell-identifier
 * name. Env-var *names* cannot be protected by quoting (a `KEY=value` prefix
 * requires the bare identifier on the left of `=`), so names must be
 * validated instead of quoted.
 */
export function isValidEnvVarName(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}
