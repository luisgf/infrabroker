package redact

// Defaults is the built-in rule set. Ordering matters: rules run in sequence
// and a segment already masked by an earlier rule is never re-masked (the
// marker-skip in apply), so more specific rules go first. All expressions are
// RE2 (linear time).
//
// Design notes:
//   - Rules that keep context (flag names, variable names, usernames) mark
//     the secret with the (?P<secret>...) group; rules where the whole token
//     is the secret (JWTs, vendor tokens, key blocks) mask the full match.
//   - The env-assignment rule requires the sensitive keyword to be a full
//     "_"-delimited component of the variable name, so AUTH matches AUTH= and
//     BASIC_AUTH= but not AUTHOR= or XAUTHORITY= (real-world false positives).
//     PWD is the exception: it demands a leading component (MYSQL_PWD=, DB_PWD=)
//     so the ubiquitous shell working-directory variable (bare PWD=) is not
//     masked out of every recording and env dump.
//   - The mysql rule covers the attached short form (mysql -psecret) — the
//     canonical example of threat-model gap #8 — and is scoped to the mysql
//     client family because a bare "-p<value>" is far too ambiguous (ports,
//     paths, profiles...).
var Defaults = []Pattern{
	{
		Name:  "flag-password",
		Regex: `(?i)--?(?:password|passwd|pwd|pass|token|secret|api[-_]?key)[= ]+(?P<secret>"[^"]+"|'[^']+'|[^\s"']+)`,
	},
	{
		Name:  "mysql-p-attached",
		Regex: `(?i)\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\n|;&]*?\s-p(?P<secret>[^\s-][^\s]*)`,
	},
	{
		Name:  "env-assignment",
		Regex: `(?i)\b(?:(?:[A-Z0-9]+_)*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)|(?:[A-Z0-9]+_)+PWD)(?:_[A-Z0-9]+)*=(?P<secret>"[^"]+"|'[^']+'|[^\s"']+)`,
	},
	{
		Name:  "uri-userinfo",
		Regex: `://[^/\s:@]+:(?P<secret>[^@\s/]+)@`,
	},
	{
		Name:  "auth-header",
		Regex: `(?i)\b(?:authorization|proxy-authorization)\b['"]?\s*[:=]\s*['"]?(?:bearer|basic|token)\s+(?P<secret>[A-Za-z0-9+/=_.~-]+)`,
	},
	{
		Name:  "curl-user",
		Regex: `(?:^|\s)(?:-u|--user)[= ]+[^\s:]+:(?P<secret>"[^"]+"|'[^']+'|[^\s"']+)`,
	},
	{
		// JWTs (three base64url segments). Also catches Kubernetes
		// ServiceAccount tokens and most OIDC access tokens.
		Name:  "jwt",
		Regex: `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`,
	},
	{
		Name:  "aws-key-id",
		Regex: `\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`,
	},
	{
		Name:  "github-token",
		Regex: `\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`,
	},
	{
		Name:  "gitlab-token",
		Regex: `\bglpat-[A-Za-z0-9_-]{20,}\b`,
	},
	{
		Name:  "slack-token",
		Regex: `\bxox[baprs]-[A-Za-z0-9-]{10,}\b`,
	},
	{
		Name:  "private-key-block",
		Regex: `-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`,
	},
}
