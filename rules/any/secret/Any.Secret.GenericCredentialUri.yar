// betterleaks v1.10.0's generic-credential-uri rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
//
// Its filter, a program Pantry runs as written (filter_expr):
//
// let isExampleValue = filter.matchesAny(finding["secret"], [
//   `(?i)^(?:(?:(?:an?|my)(?:[ _.-]|%(?:20|2d|5f))*)?example(?:(?:[ _.-]|%(?:20|2d|5f))*(?:password|passwd|pwd))?|(?:password|passwd|pwd)(?:[ _.-]|%(?:20|2d|5f))*example)(?:(?:[ _.-]|%(?:20|2d|5f))*[0-9]{1,4})?[!?.]*$`
// ]);
// let isInstructionalPlaceholder = filter.matchesAny(finding["secret"], [
//   `(?i)^(?:[a-z0-9]+[_.-])?(?:your[_.-]?(?:password|passwd|pwd)|(?:password|passwd|pwd)[_.-]goes[_.-]?here|replace[_.-]?me|insert[_.-].*[_.-]here|placeholder)$`
// ]);
// let isSyntheticExampleURI = filter.matchesAny(finding["match"], [
//   `(?i)^[a-z][a-z0-9+.-]*://(?:foo|user(?:name)?|example(?:[_.-]?user)?):(?:bar|pass(?:word)?|passwd|pwd|example(?:[_.-]?(?:password|passwd|pwd))?)@(?:(?:example|test)\.(?:com|org|net)|example\.invalid)(?::[0-9]{1,5})?(?:[/\s'"\x60#]|$)`
// ]);
// let isSyntheticCredentialTuple = filter.matchesAny(finding["match"], [
//   `(?i)^[a-z][a-z0-9+.-]*://(?:foo|test|user(?:name)?|example(?:[_.-]?user)?)[0-9]{0,4}:(?:bar|test|pass(?:word)?|passwd|pwd|token|secret)[0-9]{0,4}[!?.]?@`
// ]);
// let isTestOrDocumentationSource = filter.matchesAny(attributes["path"], [
//   `(?i)(?:^|[/\\])(?:__tests__|tests?|testdata|specs?|fixtures?|mocks?|examples?|samples?|demos?|tutorials?|templates?|qa|e2e|documentation|docs?(?:[-_][a-z0-9-]+)?)(?:[/\\]|$)`,
//   `(?i)(?:^|[/\\])readme(?:\.[^/\\]+)?$`,
//   `(?i)(?:^|[/\\])[^/\\]*(?:[_.-](?:test|spec)|(?:test|spec)[_.-])[^/\\]*\.[^/\\]+$`,
//   `(?i)\.(?:example|sample|template)(?:\.[^/\\]+)?$`,
//   `(?i)\.(?:md|mdx|rst|adoc|asciidoc)$`
// ]);
// let hasIgnoredHost = filter.matchesAny(finding["match"], [
//   `(?i)^[a-z][a-z0-9+.-]*://[^@\s]+@(?:[a-z0-9_-]+\.)*example(?:\.(?:com|org|net))?\.?(?::[0-9]{1,5})?(?:,(?:[a-z0-9_-]+\.)*example(?:\.(?:com|org|net))?\.?(?::[0-9]{1,5})?)*(?:[/?\s'"\x60#<>{}\[\];)]|,?$)`
// ]);
// let hasLowConfidenceHost = filter.matchesAny(finding["match"], [
//   `(?i)^[a-z][a-z0-9+.-]*://[^@\s]+@(?:(?:[a-z0-9_-]+\.)*example(?:\.(?:com|org|net))?|(?:[a-z0-9_-]+\.)*(?:invalid|test|localhost))\.?(?::[0-9]{1,5})?(?:,(?:(?:[a-z0-9_-]+\.)*example(?:\.(?:com|org|net))?|(?:[a-z0-9_-]+\.)*(?:invalid|test|localhost))\.?(?::[0-9]{1,5})?)*(?:[/?\s'"\x60#<>{}\[\];)]|,?$)`
// ]);
// let level = (
//   isExampleValue
//   || isSyntheticCredentialTuple
//   || isTestOrDocumentationSource
//   || hasLowConfidenceHost
// ) ? "low" : "medium";
// let _ = filter.setConfidence(level);
//
// // Discard mechanically non-literal credentials. Weak and default passwords
// // remain reportable because the URI establishes their credential role.
// isInstructionalPlaceholder
// || isSyntheticExampleURI
// || hasIgnoredHost
// || filter.matchesAny(finding["secret"], [
//   `^\*+$`,
//   `^\.+$`,
//   `(?i)^x{4,}$`,
//   `^•+$`,
//   `(?i)^\[?(?:redacted|masked|filtered)\]?$`,
//   `^\$\{.*}$`,
//   `^\$\([^\r\n]+\)$`,
//   `^#\{[^}\r\n]+}$`,
//   `^\{\{[ \t]*.+[ \t]*}}$`,
//   `^%\{[^}]+}$`,
//   `^\$[A-Za-z_][A-Za-z0-9_]*$`,
//   `(?i)^\$env:[A-Za-z_][A-Za-z0-9_]*$`,
//   `^%[A-Za-z_][A-Za-z0-9_]*%$`,
//   `^<[^>]+>$`,
//   `^\[[A-Za-z_][A-Za-z0-9_.-]*]$`,
//   `^\{[^}]+}$`,
//   `(?:\$\{|#\{|\{\{|%\{)`
// ])

rule Any_Secret_GenericCredentialUri
{
    meta:
        description  = "Detected a password embedded in a service connection URI, which may expose direct access to the referenced service."
        author       = "betterleaks"
        reference    = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license      = "MIT"
        os           = "any"
        category     = "secret"
        family       = "GenericCredentialUri"
        severity     = "medium"
        score        = 50
        id           = "generic-credential-uri"
        confidence   = "medium"
        keyword      = "http://"
        keyword      = "https://"
        keyword      = "postgres://"
        keyword      = "postgresql://"
        keyword      = "mysql://"
        keyword      = "mariadb://"
        keyword      = "mongodb://"
        keyword      = "mongodb+srv://"
        keyword      = "redis://"
        keyword      = "rediss://"
        keyword      = "amqp://"
        keyword      = "amqps://"
        keyword      = "ldap://"
        keyword      = "ldaps://"
        keyword      = "smtp://"
        keyword      = "smtps://"
        keyword      = "ftp://"
        keyword      = "ftps://"
        keyword      = "ssh://"
        secret_group = 4
        specificity  = 30
        filter_expr  = "let isExampleValue = filter.matchesAny(finding[\"secret\"], [\n  `(?i)^(?:(?:(?:an?|my)(?:[ _.-]|%(?:20|2d|5f))*)?example(?:(?:[ _.-]|%(?:20|2d|5f))*(?:password|passwd|pwd))?|(?:password|passwd|pwd)(?:[ _.-]|%(?:20|2d|5f))*example)(?:(?:[ _.-]|%(?:20|2d|5f))*[0-9]{1,4})?[!?.]*$`\n]);\nlet isInstructionalPlaceholder = filter.matchesAny(finding[\"secret\"], [\n  `(?i)^(?:[a-z0-9]+[_.-])?(?:your[_.-]?(?:password|passwd|pwd)|(?:password|passwd|pwd)[_.-]goes[_.-]?here|replace[_.-]?me|insert[_.-].*[_.-]here|placeholder)$`\n]);\nlet isSyntheticExampleURI = filter.matchesAny(finding[\"match\"], [\n  `(?i)^[a-z][a-z0-9+.-]*://(?:foo|user(?:name)?|example(?:[_.-]?user)?):(?:bar|pass(?:word)?|passwd|pwd|example(?:[_.-]?(?:password|passwd|pwd))?)@(?:(?:example|test)\\.(?:com|org|net)|example\\.invalid)(?::[0-9]{1,5})?(?:[/\\s'\"\\x60#]|$)`\n]);\nlet isSyntheticCredentialTuple = filter.matchesAny(finding[\"match\"], [\n  `(?i)^[a-z][a-z0-9+.-]*://(?:foo|test|user(?:name)?|example(?:[_.-]?user)?)[0-9]{0,4}:(?:bar|test|pass(?:word)?|passwd|pwd|token|secret)[0-9]{0,4}[!?.]?@`\n]);\nlet isTestOrDocumentationSource = filter.matchesAny(attributes[\"path\"], [\n  `(?i)(?:^|[/\\\\])(?:__tests__|tests?|testdata|specs?|fixtures?|mocks?|examples?|samples?|demos?|tutorials?|templates?|qa|e2e|documentation|docs?(?:[-_][a-z0-9-]+)?)(?:[/\\\\]|$)`,\n  `(?i)(?:^|[/\\\\])readme(?:\\.[^/\\\\]+)?$`,\n  `(?i)(?:^|[/\\\\])[^/\\\\]*(?:[_.-](?:test|spec)|(?:test|spec)[_.-])[^/\\\\]*\\.[^/\\\\]+$`,\n  `(?i)\\.(?:example|sample|template)(?:\\.[^/\\\\]+)?$`,\n  `(?i)\\.(?:md|mdx|rst|adoc|asciidoc)$`\n]);\nlet hasIgnoredHost = filter.matchesAny(finding[\"match\"], [\n  `(?i)^[a-z][a-z0-9+.-]*://[^@\\s]+@(?:[a-z0-9_-]+\\.)*example(?:\\.(?:com|org|net))?\\.?(?::[0-9]{1,5})?(?:,(?:[a-z0-9_-]+\\.)*example(?:\\.(?:com|org|net))?\\.?(?::[0-9]{1,5})?)*(?:[/?\\s'\"\\x60#<>{}\\[\\];)]|,?$)`\n]);\nlet hasLowConfidenceHost = filter.matchesAny(finding[\"match\"], [\n  `(?i)^[a-z][a-z0-9+.-]*://[^@\\s]+@(?:(?:[a-z0-9_-]+\\.)*example(?:\\.(?:com|org|net))?|(?:[a-z0-9_-]+\\.)*(?:invalid|test|localhost))\\.?(?::[0-9]{1,5})?(?:,(?:(?:[a-z0-9_-]+\\.)*example(?:\\.(?:com|org|net))?|(?:[a-z0-9_-]+\\.)*(?:invalid|test|localhost))\\.?(?::[0-9]{1,5})?)*(?:[/?\\s'\"\\x60#<>{}\\[\\];)]|,?$)`\n]);\nlet level = (\n  isExampleValue\n  || isSyntheticCredentialTuple\n  || isTestOrDocumentationSource\n  || hasLowConfidenceHost\n) ? \"low\" : \"medium\";\nlet _ = filter.setConfidence(level);\n\n// Discard mechanically non-literal credentials. Weak and default passwords\n// remain reportable because the URI establishes their credential role.\nisInstructionalPlaceholder\n|| isSyntheticExampleURI\n|| hasIgnoredHost\n|| filter.matchesAny(finding[\"secret\"], [\n  `^\\*+$`,\n  `^\\.+$`,\n  `(?i)^x{4,}$`,\n  `^\xe2\x80\xa2+$`,\n  `(?i)^\\[?(?:redacted|masked|filtered)\\]?$`,\n  `^\\$\\{.*}$`,\n  `^\\$\\([^\\r\\n]+\\)$`,\n  `^#\\{[^}\\r\\n]+}$`,\n  `^\\{\\{[ \\t]*.+[ \\t]*}}$`,\n  `^%\\{[^}]+}$`,\n  `^\\$[A-Za-z_][A-Za-z0-9_]*$`,\n  `(?i)^\\$env:[A-Za-z_][A-Za-z0-9_]*$`,\n  `^%[A-Za-z_][A-Za-z0-9_]*%$`,\n  `^<[^>]+>$`,\n  `^\\[[A-Za-z_][A-Za-z0-9_.-]*]$`,\n  `^\\{[^}]+}$`,\n  `(?:\\$\\{|#\\{|\\{\\{|%\\{)`\n])"

    strings:
        $secret = /\b(([hH][tT][tT][pP][sS]?|[pP][oO][sS][tT][gG][rR][eE][sS](?:[qQ][lL])?|[mM][yY][sS][qQ][lL]|[mM][aA][rR][iI][aA][dD][bB]|[mM][oO][nN][gG][oO][dD][bB](?:\+[sS][rR][vV])?|[rR][eE][dD][iI][sS][sS]?|[aA][mM][qQ][pP][sS]?|[lL][dD][aA][pP][sS]?|[sS][mM][tT][pP][sS]?|[fF][tT][pP][sS]?|[sS][sS][hH]):\/\/([^:\/@\s'"\x60]{0,128}):([^\/@\s'"\x60]{1,256})@((?:\[[A-F0-9a-f:.%]+\]|[A-Za-z0-9][A-Za-z0-9._-]{0,252}))(?::[0-9]{1,5})?(?:,(?:\[[A-F0-9a-f:.%]+\]|[A-Za-z0-9][A-Za-z0-9._-]{0,252})(?::[0-9]{1,5})?)*(?:[\/?][A-Za-z0-9._~!$&(*+,;=:@%\/?-]*)?)(?:[\s'"\x60#<>\{\}\[\],;)]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
