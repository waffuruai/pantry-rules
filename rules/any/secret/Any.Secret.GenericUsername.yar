// betterleaks v1.10.0's generic-username rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
//
// Its filter, a program Pantry runs as written (filter_expr):
//
// // An unquoted value is an ambiguous scalar in configuration, but
// // not a string literal in the source languages recognized below.
// let isCodeFile = filter.matchesAny(attributes["path"], [
//   `(?i)\.(?:c|cc|cpp|cxx|h|hh|hpp|cs|dart|ex|exs|fs|fsx|go|gemspec|groovy|java|js|jsx|mjs|cjs|kt|kts|lua|m|mm|php|pl|pm|py|pyw|r|rake|rb|rs|scala|sql|swift|tf|tfvars|ts|tsx|vb|vue)(?:\.(?:example|sample|template))?$`
// ]);
// let isUnquotedCodeValue = isCodeFile && filter.matchesAny(finding["match"], [
//   `^(?:[^a-zA-Z0-9])?(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]?name)?|client(?:[_.-]?(?:id|name))?)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]*[^\x22\x27\x60 \t\r\n]`
// ]);
//
// isUnquotedCodeValue
// || filter.matchesAny(finding["secret"], [
//   `^\*+$`,
//   `^\.+$`,
//   `(?i)^x{4,}$`,
//   `^•+$`,
//   `^\$\{.*}$`,
//   `^\$\([^\r\n]+\)$`,
//   `^#\{[^}\r\n]+}$`,
//   `^\{\{[ \t]*.+[ \t]*}}$`,
//   `^%\{[^}]+}$`,
//   `^<[^>]+>$`,
//   `^<[^>\s]+$`,
//   `^\{[^}]+}$`,
//   `(?i)^\[?(?:redacted|masked|filtered)\]?$`,
//   `^(?:USERNAME|USER_NAME|USER|LOGIN|LOGIN_NAME|ACCOUNT_NAME|EMAIL|EMAIL_ADDRESS|UID|CLIENT|CLIENT_ID|CLIENT_NAME)$`,
//   `(?i)^(?:your|example)[_-]?(?:username|user_name|user|login|login_name|account_name|email|email_address|uid|client(?:_id|_name)?)$`
// ])
// || filter.matchesAny(finding["match"], [
//   `^(?:[^a-zA-Z0-9])?(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]name)?|client(?:[_.-]?(?:id|name))?)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]*(?i:nil|null|none|undefined|true|false|string|str|text|integer|int|number|boolean|bool|object)(?:[ \t]*[,;)}\]\r\n]|[ \t]*$|\\[nr])`,
//   `^(?:[^a-zA-Z0-9])?(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]name)?|client(?:[_.-]?(?:id|name))?)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]*(?:[$@][A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*|\[[^]\r\n]+\]|\([^,\r\n)]*\)?)*|:[A-Za-z_][A-Za-z0-9_]*|(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*::[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*|(?i:process\.env|config|settings|credentials?|secrets?|var|local|module|data)(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*|\[[^]\r\n]+\])+|[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^]\r\n]+\]|\([^,\r\n)]*\)?)(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*|\[[^]\r\n]+\]|\([^,\r\n)]*\)?)*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*\.(?i:(?:[a-z0-9]+_)*(?:username|user|login(?:_name)?|email(?:_address)?|uid|account(?:_name)?|client(?:_(?:id|name))?|id)))[)}\]]*\\?(?:[ \t]*[,;)}\]\r\n]|[ \t]*$|\\[nr])`
// ])

private rule Any_Secret_GenericUsername
{
    meta:
        description = "Detected a username-like value used as a component of the generic-password rule."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "GenericUsername"
        severity    = "low"
        score       = 30
        id          = "generic-username"
        confidence  = "low"
        keyword     = "user"
        keyword     = "login"
        keyword     = "email"
        keyword     = "uid"
        keyword     = "account"
        keyword     = "client"
        filter_expr = "// An unquoted value is an ambiguous scalar in configuration, but\n// not a string literal in the source languages recognized below.\nlet isCodeFile = filter.matchesAny(attributes[\"path\"], [\n  `(?i)\\.(?:c|cc|cpp|cxx|h|hh|hpp|cs|dart|ex|exs|fs|fsx|go|gemspec|groovy|java|js|jsx|mjs|cjs|kt|kts|lua|m|mm|php|pl|pm|py|pyw|r|rake|rb|rs|scala|sql|swift|tf|tfvars|ts|tsx|vb|vue)(?:\\.(?:example|sample|template))?$`\n]);\nlet isUnquotedCodeValue = isCodeFile && filter.matchesAny(finding[\"match\"], [\n  `^(?:[^a-zA-Z0-9])?(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]?name)?|client(?:[_.-]?(?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*[^\\x22\\x27\\x60 \\t\\r\\n]`\n]);\n\nisUnquotedCodeValue\n|| filter.matchesAny(finding[\"secret\"], [\n  `^\\*+$`,\n  `^\\.+$`,\n  `(?i)^x{4,}$`,\n  `^\xe2\x80\xa2+$`,\n  `^\\$\\{.*}$`,\n  `^\\$\\([^\\r\\n]+\\)$`,\n  `^#\\{[^}\\r\\n]+}$`,\n  `^\\{\\{[ \\t]*.+[ \\t]*}}$`,\n  `^%\\{[^}]+}$`,\n  `^<[^>]+>$`,\n  `^<[^>\\s]+$`,\n  `^\\{[^}]+}$`,\n  `(?i)^\\[?(?:redacted|masked|filtered)\\]?$`,\n  `^(?:USERNAME|USER_NAME|USER|LOGIN|LOGIN_NAME|ACCOUNT_NAME|EMAIL|EMAIL_ADDRESS|UID|CLIENT|CLIENT_ID|CLIENT_NAME)$`,\n  `(?i)^(?:your|example)[_-]?(?:username|user_name|user|login|login_name|account_name|email|email_address|uid|client(?:_id|_name)?)$`\n])\n|| filter.matchesAny(finding[\"match\"], [\n  `^(?:[^a-zA-Z0-9])?(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]name)?|client(?:[_.-]?(?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?i:nil|null|none|undefined|true|false|string|str|text|integer|int|number|boolean|bool|object)(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`,\n  `^(?:[^a-zA-Z0-9])?(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]name)?|client(?:[_.-]?(?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?:[$@][A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|:[A-Za-z_][A-Za-z0-9_]*|(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*::[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*|(?i:process\\.env|config|settings|credentials?|secrets?|var|local|module|data)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\])+|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*(?:\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*\\.(?i:(?:[a-z0-9]+_)*(?:username|user|login(?:_name)?|email(?:_address)?|uid|account(?:_name)?|client(?:_(?:id|name))?|id)))[)}\\]]*\\\\?(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`\n])"

    strings:
        $secret = /(?:^|[^a-zA-Z0-9])(?:[uU][sS][eE][rR][nN][aA][mM][eE]|[uU][sS][eE][rR]|[lL][oO][gG][iI][nN](?:[_.-]?[nN][aA][mM][eE])?|[eE][mM][aA][iI][lL](?:[_.-]?[aA][dD][dD][rR][eE][sS][sS])?|[uU][iI][dD]|[aA][cC][cC][oO][uU][nN][tT](?:[_.-]?[nN][aA][mM][eE])?|[cC][lL][iI][eE][nN][tT](?:[_.-]?(?:[iI][dD]|[nN][aA][mM][eE]))?)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]{0,5}(?:"((?:\\.|[^"\\\r\n]){3,250})"|'((?:\\.|[^'\\\r\n]){3,250})'|\x60((?:\\.|[^\x60\\\r\n]){3,250})\x60|([^:=\s'"\x60,;][^\s'"\x60,;]{2,249}))(?:[ \t]*[,;)\}\]\r\n]|[ \t]*$|\\[nr])/  // gitleaks:allow

    condition:
        $secret
}
