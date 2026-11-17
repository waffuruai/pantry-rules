// betterleaks v1.10.0's generic-password rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
//
// Its filter, a program Pantry runs as written (filter_expr):
//
// // Restrict nearby evidence to the password's line and the
// // six lines on either side. The password key itself is intentionally excluded
// // from the evidence patterns below.
// let raw = finding["fragment_raw"];
// let beforeLines = split(raw[
//   max(finding["match_start_idx"] - 8192, 0):finding["match_start_idx"]
// ], "\n");
// let afterLines = split(raw[
//   finding["match_end_idx"]:min(finding["match_end_idx"] + 8192, len(raw))
// ], "\n");
// let nearbyContext =
//   join(beforeLines[max(len(beforeLines) - 7, 0):], "\n")
//   + "\n"
//   + join(afterLines[:min(len(afterLines), 7)], "\n");
// let linePrefix = beforeLines[len(beforeLines) - 1];
//
// let hasAuthContext = filter.matchesAny(nearbyContext, [
//   // Authentication and connection calls.
//   `(?i)(?:^|[^a-z0-9])(?:auth(?:enticate|entication)?|login|log[_.-]?in|sign[_.-]?in|connect(?:ion)?|open[_.-]?(?:connection|session)|create[_.-]?(?:connection|session)|bind)\b[ \t]*\(`,
//   // Credential and connection configuration containers.
//   `(?i)(?:^|[^a-z0-9])(?:basic[_.-]?auth|auth(?:entication)?[_.-]?(?:config|options|params)|credentials?|login[_.-]?(?:config|options|params)|connection[_.-]?(?:string|config|options|params)|data[_.-]?source|dsn)\b[ \t'"\\]{0,3}(?:=>|:=|=|:|\{|\()`,
//   // Assets commonly paired with credentials.
//   `(?i)(?:^|[^a-z0-9])(?:host(?:name)?|server|endpoint|database|db[_.-]?(?:name|host|url)?|port|jdbc[_.-]?url|connection[_.-]?url)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]{0,5}(?:"[^"\r\n]+"|'[^'\r\n]+'|\x60[^\x60\r\n]+\x60|[^\s,;)}\]]+)`,
//   // Nearby connection URI or service context.
//   `(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|ldaps?|smtps?|ftps?|ssh)://`
// ]);
// let hasIdentityFieldContext = filter.matchesAny(nearbyContext, [
//   `(?im)(?:^|[^a-z0-9])(?:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]?name)?|client(?:[_.-]?(?:id|name))?)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)`
// ]);
// let isDirectAuthArgument = filter.matchesAny(finding["match"], [
//   `(?i)^(?:login|log_in)\b[ \t]*\(`,
//   `(?i)^authenticate\b[ \t]*\([ \t]*[^,\r\n]*(?:user(?:name)?|account|email|login|uid)[^,\r\n]*,`
// ]);
// let isCommented = filter.matchesAny(linePrefix, [
//   `(?:^[ \t]*(?:#|//|/\*|\*|--|;|<!--)|[ \t](?:#|//|/\*|--|<!--)[ \t]*)`
// ]);
// let isInstructionalPlaceholder = filter.matchesAny(finding["secret"], [
//   `^(?:PGPASSWORD|[A-Z][A-Z0-9_]*_(?:PASSWORD|PASSWD|PWD)(?:_[A-Z0-9]+)*|(?:PASSWORD|PASSWD|PWD)_[A-Z0-9_]+)$`,
//   `(?i)^(?:(?:(?:an?|my)[ _.-]*)?example(?:[ _.-]*(?:password|passwd|pwd))?|(?:password|passwd|pwd)[ _.-]*example)(?:[ _.-]*[0-9]{1,4})?[!?.]*$`,
//   `(?i)^(?:password|passwd|pwd)?[ _-]?(?:goes[ _-]?here|replace[ _-]?me|insert[ _-].*here|not[ _-]?set)$`
// ]);
// let isCodeFile = filter.matchesAny(attributes["path"], [
//   `(?i)\.(?:c|cc|cpp|cxx|h|hh|hpp|cs|dart|ex|exs|fs|fsx|go|gemspec|groovy|java|js|jsx|mjs|cjs|kt|kts|lua|m|mm|php|pl|pm|py|pyw|r|rake|rb|rs|scala|sql|swift|tf|tfvars|ts|tsx|vb|vue)(?:\.(?:example|sample|template))?$`
// ]);
// let isUnquotedAssignment = filter.matchesAny(finding["match"], [
//   `^(?i:passw(?:or)?d|psw|[_.-]pw)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]*[^\x22\x27\x60 \t\r\n]`
// ]);
// let isUnquotedCodeValue = isCodeFile && isUnquotedAssignment;
// let isUnquotedExpression = isUnquotedAssignment && filter.matchesAny(finding["secret"], [
//   `^[A-Za-z_][A-Za-z0-9_-]*:\[[^]\r\n]+\]$`,
//   `^[A-Za-z_][A-Za-z0-9_]*[)}\]]+(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)*$`
// ]);
// let hasNonPlaintextPasswordContext = filter.matchesAny(linePrefix + finding["match"], [
//   `(?i)(?:^|[^a-z0-9])(?:enc|encrypt(?:ed|ion)?|hash(?:ed)?|encod(?:e|ed|ing)|cipher(?:text)?|seal(?:ed)?|vault(?:ed)?)(?:[_.-][a-z0-9]+){0,5}[_.-]?password\b`,
//   `(?i)(?:^|[^a-z0-9])password[_.-]?(?:cipher(?:text)?|hash|digest|algorithm|scheme|encoding|format)\b`
// ]);
// let hasNestedUnquotedAssignment = filter.matchesAny(finding["match"], [
//   `^(?i:passw(?:or)?d|psw|[_.-]pw)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]{0,5}[^"'\x60\r\n]*[.,][A-Za-z_][A-Za-z0-9_-]*=`
// ]);
// let isEncryptedValue = filter.matchesAny(finding["secret"], [
//   // Serialized encryption envelopes and armored ciphertext.
//   `(?i)^ENC\[[A-Z0-9][A-Z0-9_.+/-]*(?:,|\]|$)`,
//   `(?i)^ENC\([A-Z0-9+/=_:.,-]{8,}\)$`,
//   `(?i)^\{cipher\}.{4,}$`,
//   `^\$ANSIBLE_VAULT(?:;|$)`,
//   `(?i)^!vault$`,
//   `^age-encryption\.org/v[0-9]+$`,
//   `^-----BEGIN (?:AGE ENCRYPTED FILE|PGP MESSAGE|ENCRYPTED PRIVATE KEY)-----$`,
//   // OpenSSL salted output, HashiCorp Vault transit ciphertext, and Fernet.
//   `^U2FsdGVkX1[A-Za-z0-9+/=]{8,}$`,
//   `^vault:v[0-9]+:[A-Za-z0-9+/=_-]{8,}$`,
//   `^gAAAAA[A-Za-z0-9_-]{70,}={0,2}$`,
//   // Compact JWE and encrypted PASETO (local-purpose) tokens.
//   `^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$`,
//   `^v[124]\.local\.[A-Za-z0-9_-]{32,}(?:\.[A-Za-z0-9_-]+)?$`,
//   // Windows DPAPI blobs in Base64 or exported SecureString hex form.
//   `^AQAAANCMnd8BFdERjHoAwE/Cl\+sBA[A-Za-z0-9+/=]{16,}$`,
//   `(?i)^01000000d08c9ddf0115d1118c7a00c04fc297eb01[0-9a-f]{16,}$`
// ]);
// let isCryptographicAlgorithm = filter.matchesAny(finding["secret"], [
//   // Common block ciphers with key sizes and/or modes.
//   `(?i)^(?:AES|RIJNDAEL|ARIA|CAMELLIA)[-_/]?(?:128|192|256)(?:[-_/](?:ECB|CBC(?:[-_/]HMAC[-_/]SHA[-_]?(?:256|384|512))?|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM|GMAC|EAX|OCB|SIV|GCM[-_]?SIV|XTS|KW|KWP))?$`,
//   `(?i)^(?:AES|RIJNDAEL|ARIA|CAMELLIA)[-_/]?(?:ECB|CBC|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM|GMAC|EAX|OCB|SIV|GCM[-_]?SIV|XTS|KW|KWP)$`,
//   `(?i)^(?:(?:RIJNDAEL|ARIA|CAMELLIA|DES(?:[-_]?(?:EDE3?|3|X))?|DESEDE|3DES|TRIPLE[-_]?DES|BLOWFISH|BF|TWOFISH|SERPENT|CAST(?:5|128|256)?|IDEA|SEED|SM4|RC[2456]|ARCFOUR)[-_/](?:ECB|CBC|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM|GMAC|EAX|OCB|SIV|GCM[-_]?SIV|XTS|KW|KWP)|X?(?:CHACHA20|SALSA20)[-_/]POLY1305|AESWRAP(?:[-_]?(?:128|192|256))?|DESEDEWRAP)$`,
//   // Java Cryptography Architecture transformations and PBE names.
//   `(?i)^(?:AES(?:[-_]?(?:128|192|256))?|ARIA(?:[-_]?(?:128|192|256))?|CAMELLIA(?:[-_]?(?:128|192|256))?|BLOWFISH|DES|DESEDE|RC2|RSA)/(?:ECB|CBC|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM)/(?:NO|PKCS[157]|ISO10126|OAEPWITH(?:MD5|SHA[-_]?(?:1|224|256|384|512))ANDMGF1)PADDING$`,
//   `(?i)^PBEWITH(?:HMAC)?(?:MD5|SHA(?:1|224|256|384|512))AND(?:AES(?:[-_]?(?:128|256))?|DES(?:EDE)?|TRIPLEDES|RC[24](?:[-_]?(?:40|128))?)$`,
//   // JOSE/JWE key-management and content-encryption identifiers.
//   `(?i)^(?:RSA1_5|RSA-OAEP(?:-(?:256|384|512))?|ECDH-ES(?:\+A(?:128|192|256)(?:GCM)?KW)?|A(?:128|192|256)(?:KW|GCMKW|GCM|CBC-HS(?:256|384|512))|PBES2-HS(?:256|384|512)\+A(?:128|192|256)KW)$`,
//   // Other explicit asymmetric encryption and key-wrapping descriptors.
//   `(?i)^(?:RSA(?:ES)?[-_/](?:OAEP(?:[-_/](?:MD5|SHA[-_]?(?:1|224|256|384|512)))?|PKCS1(?:[-_]?V?1[_.]5)?|NO[-_]?PADDING)|ECIES(?:[-_/](?:P(?:256|384|521)|SECP(?:256K1|256R1|384R1|521R1)))?|ELGAMAL[-_/](?:ECB|OAEP|PKCS1)|SM2[-_/](?:C1C2C3|C1C3C2))$`,
//   // Composite hash, MAC, signature, and password-derivation identifiers.
//   `(?i)^(?:HMAC[-_]?(?:MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512))|PBKDF2[-_/](?:HMAC[-_]?)?(?:SHA[-_]?(?:1|224|256|384|512))|HKDF[-_/]SHA[-_]?(?:1|224|256|384|512)|(?:RSA|DSA|ECDSA|ED25519)[-_/](?:MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512))|(?:MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512))[-_/](?:RSA|DSA|ECDSA|ED25519))$`,
//   // TLS and OpenSSH cipher-suite identifiers.
//   `(?i)^TLS_(?:(?:AES_(?:128|256)_GCM|CHACHA20_POLY1305)_SHA(?:256|384)|[A-Z0-9]+(?:_[A-Z0-9]+)*_WITH_[A-Z0-9]+(?:_[A-Z0-9]+)*)$`,
//   `(?i)^(?:AES(?:128|192|256)-(?:CBC|CTR|GCM)|CHACHA20-POLY1305)@OPENSSH\.COM$`
// ]);
// let isContextualAlgorithmName = hasNonPlaintextPasswordContext && filter.matchesAny(finding["secret"], [
//   // A field name can disambiguate an exact algorithm name, but cannot by
//   // itself prove that an arbitrary value is encrypted or hashed.
//   `(?i)^(?:AES|RIJNDAEL|ARIA|CAMELLIA|CHACHA20|XCHACHA20|SALSA20|XSALSA20|DES|DESEDE|3DES|TRIPLE[-_]?DES|TWOFISH|SERPENT|CAST(?:5|128|256)|IDEA|SEED|SM4|RC[2456]|ARCFOUR|RSA|ECIES|ELGAMAL|SM2|MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512)|BLAKE2[BS](?:[-_]?(?:256|512))?|BLAKE3|RIPEMD[-_]?(?:128|160|256|320)|WHIRLPOOL|SM3|PBKDF2|SCRYPT|BCRYPT|ARGON2(?:D|I|ID)?|HKDF|YESCRYPT)$`
// ]);
// let level = (
//   (
//     isDirectAuthArgument
//     || (hasAuthContext && hasIdentityFieldContext)
//   )
//   && !isCommented
//   && !isInstructionalPlaceholder
// ) ? "medium" : "low";
// let _ = filter.setConfidence(level);
//
// filter.matchesAny(finding["secret"], [
//   `^\*+$`,
//   `^\.+$`,
//   `(?i)^x{4,}$`,
//   `(?i)^\[?(?:redacted|masked|filtered)\]?$`,
//   `^•+$`,
//   `^\$\{.*}$`,
//   `^\$\([^\r\n]+\)$`,
//   `^#\{[^}\r\n]+}$`,
//   `^\{\{[ \t]*.+[ \t]*}}$`,
//   `^%\{[^}]+}$`,
//   `^\$[A-Za-z_][A-Za-z0-9_]*$`,
//   `(?i)^\$env:[A-Za-z_][A-Za-z0-9_]*$`,
//   `^%[A-Za-z_][A-Za-z0-9_]*%$`,
//   `^<[^>]+>$`,
//   `^<[^>\s]+$`,
//   `^\{[^}]+}$`,
//   `(?i)^(?:your[_-]?password|placeholder|forbidden_value)$`,
//   `^\([A-Za-z_][A-Za-z0-9_.]*(?:[ \t]+[A-Za-z_][A-Za-z0-9_.]*)*\)$`,
//   `^\$\(`,
//   `(?:\$\{|#\{|\{\{|%\{)`,
//   `%\([A-Za-z_][A-Za-z0-9_]*\)[#0 +\-]?[0-9.]*(?:[diouxXeEfFgGcrs%])`,
//   `(?i)^--?passw(?:or)?d$`,
//   `^\$2[abxy]\$[0-9]{2}\$[./A-Za-z0-9]{7,}$`,
//   `(?i)^\$pbkdf2[-_][^$]+\$.*$`,
//   `(?i)^(?:pbkdf2_(?:sha1|sha256)|bcrypt_sha256|argon2|scrypt|sha1|md5|crypt)\$`,
//   `(?i)^\$(?:1|5|6|7|y|gy|argon2(?:d|i|id)|scrypt|pbkdf2(?:[-_]sha(?:1|224|256|384|512))?|apr1)\$`,
//   `^\$[PH]\$[./A-Za-z0-9]{20,}$`,
//   `(?i)^\{(?:SSHA(?:256|384|512)?|SHA(?:256|384|512)?|MD5|CRYPT|BCRYPT|PBKDF2)}`,
//   `(?i)^SCRAM-SHA-(?:1|256|512)\$`,
//   `(?i)^md5[0-9a-f]{32}$`,
//   `^\*[0-9A-F]{40}$`
// ])
// || isEncryptedValue
// || isCryptographicAlgorithm
// || isContextualAlgorithmName
// || isUnquotedCodeValue
// || isUnquotedExpression
// || hasNestedUnquotedAssignment
// || filter.matchesAny(finding["match"], [
//   `^(?i:passw(?:or)?d|psw|[_.-]pw)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]*(?i:nil|null|none|undefined|true|false|string|str|text|integer|int|number|boolean|bool|object)(?:[ \t]*[,;)}\]\r\n]|[ \t]*$|\\[nr])`,
//   `^(?i:passw(?:or)?d|psw|[_.-]pw)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]*(?:[$@][A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*|\[[^]\r\n]+\]|\([^,\r\n)]*\)?)*|:[A-Za-z_][A-Za-z0-9_]*|(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*::[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*|(?i:process\.env|config|settings|credentials?|secrets?|var|local|module|data)(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*|\[[^]\r\n]+\])+|[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*(?:\[[^]\r\n]+\]|\([^,\r\n)]*\)?)(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*|\[[^]\r\n]+\]|\([^,\r\n)]*\)?)*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*\.(?i:(?:[a-z0-9]+_)*(?:passw(?:or)?d|psw|token|secret|hex)))[)}\]]*\\?(?:[ \t]*[,;)}\]\r\n]|[ \t]*$|\\[nr])`
// ])

rule Any_Secret_GenericPassword
{
    meta:
        description         = "Detected a potential hardcoded password literal, which may expose account credentials."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "GenericPassword"
        severity            = "low"
        score               = 30
        id                  = "generic-password"
        confidence          = "low"
        keyword             = "passw"
        keyword             = "psw"
        keyword             = "_pw"
        keyword             = "-pw"
        keyword             = ".pw"
        keyword             = "login("
        keyword             = "login ("
        keyword             = "log_in("
        keyword             = "log_in ("
        keyword             = "authenticate("
        keyword             = "authenticate ("
        specificity         = 20
        component1          = "generic-username"
        component1_within   = "7L,200C"
        component1_optional = true
        filter_expr         = "// Restrict nearby evidence to the password's line and the\n// six lines on either side. The password key itself is intentionally excluded\n// from the evidence patterns below.\nlet raw = finding[\"fragment_raw\"];\nlet beforeLines = split(raw[\n  max(finding[\"match_start_idx\"] - 8192, 0):finding[\"match_start_idx\"]\n], \"\\n\");\nlet afterLines = split(raw[\n  finding[\"match_end_idx\"]:min(finding[\"match_end_idx\"] + 8192, len(raw))\n], \"\\n\");\nlet nearbyContext =\n  join(beforeLines[max(len(beforeLines) - 7, 0):], \"\\n\")\n  + \"\\n\"\n  + join(afterLines[:min(len(afterLines), 7)], \"\\n\");\nlet linePrefix = beforeLines[len(beforeLines) - 1];\n\nlet hasAuthContext = filter.matchesAny(nearbyContext, [\n  // Authentication and connection calls.\n  `(?i)(?:^|[^a-z0-9])(?:auth(?:enticate|entication)?|login|log[_.-]?in|sign[_.-]?in|connect(?:ion)?|open[_.-]?(?:connection|session)|create[_.-]?(?:connection|session)|bind)\\b[ \\t]*\\(`,\n  // Credential and connection configuration containers.\n  `(?i)(?:^|[^a-z0-9])(?:basic[_.-]?auth|auth(?:entication)?[_.-]?(?:config|options|params)|credentials?|login[_.-]?(?:config|options|params)|connection[_.-]?(?:string|config|options|params)|data[_.-]?source|dsn)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:|\\{|\\()`,\n  // Assets commonly paired with credentials.\n  `(?i)(?:^|[^a-z0-9])(?:host(?:name)?|server|endpoint|database|db[_.-]?(?:name|host|url)?|port|jdbc[_.-]?url|connection[_.-]?url)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]{0,5}(?:\"[^\"\\r\\n]+\"|'[^'\\r\\n]+'|\\x60[^\\x60\\r\\n]+\\x60|[^\\s,;)}\\]]+)`,\n  // Nearby connection URI or service context.\n  `(?i)\\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|amqps?|ldaps?|smtps?|ftps?|ssh)://`\n]);\nlet hasIdentityFieldContext = filter.matchesAny(nearbyContext, [\n  `(?im)(?:^|[^a-z0-9])(?:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]?name)?|client(?:[_.-]?(?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)`\n]);\nlet isDirectAuthArgument = filter.matchesAny(finding[\"match\"], [\n  `(?i)^(?:login|log_in)\\b[ \\t]*\\(`,\n  `(?i)^authenticate\\b[ \\t]*\\([ \\t]*[^,\\r\\n]*(?:user(?:name)?|account|email|login|uid)[^,\\r\\n]*,`\n]);\nlet isCommented = filter.matchesAny(linePrefix, [\n  `(?:^[ \\t]*(?:#|//|/\\*|\\*|--|;|<!--)|[ \\t](?:#|//|/\\*|--|<!--)[ \\t]*)`\n]);\nlet isInstructionalPlaceholder = filter.matchesAny(finding[\"secret\"], [\n  `^(?:PGPASSWORD|[A-Z][A-Z0-9_]*_(?:PASSWORD|PASSWD|PWD)(?:_[A-Z0-9]+)*|(?:PASSWORD|PASSWD|PWD)_[A-Z0-9_]+)$`,\n  `(?i)^(?:(?:(?:an?|my)[ _.-]*)?example(?:[ _.-]*(?:password|passwd|pwd))?|(?:password|passwd|pwd)[ _.-]*example)(?:[ _.-]*[0-9]{1,4})?[!?.]*$`,\n  `(?i)^(?:password|passwd|pwd)?[ _-]?(?:goes[ _-]?here|replace[ _-]?me|insert[ _-].*here|not[ _-]?set)$`\n]);\nlet isCodeFile = filter.matchesAny(attributes[\"path\"], [\n  `(?i)\\.(?:c|cc|cpp|cxx|h|hh|hpp|cs|dart|ex|exs|fs|fsx|go|gemspec|groovy|java|js|jsx|mjs|cjs|kt|kts|lua|m|mm|php|pl|pm|py|pyw|r|rake|rb|rs|scala|sql|swift|tf|tfvars|ts|tsx|vb|vue)(?:\\.(?:example|sample|template))?$`\n]);\nlet isUnquotedAssignment = filter.matchesAny(finding[\"match\"], [\n  `^(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*[^\\x22\\x27\\x60 \\t\\r\\n]`\n]);\nlet isUnquotedCodeValue = isCodeFile && isUnquotedAssignment;\nlet isUnquotedExpression = isUnquotedAssignment && filter.matchesAny(finding[\"secret\"], [\n  `^[A-Za-z_][A-Za-z0-9_-]*:\\[[^]\\r\\n]+\\]$`,\n  `^[A-Za-z_][A-Za-z0-9_]*[)}\\]]+(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*(?:\\([^)]*\\))?)*$`\n]);\nlet hasNonPlaintextPasswordContext = filter.matchesAny(linePrefix + finding[\"match\"], [\n  `(?i)(?:^|[^a-z0-9])(?:enc|encrypt(?:ed|ion)?|hash(?:ed)?|encod(?:e|ed|ing)|cipher(?:text)?|seal(?:ed)?|vault(?:ed)?)(?:[_.-][a-z0-9]+){0,5}[_.-]?password\\b`,\n  `(?i)(?:^|[^a-z0-9])password[_.-]?(?:cipher(?:text)?|hash|digest|algorithm|scheme|encoding|format)\\b`\n]);\nlet hasNestedUnquotedAssignment = filter.matchesAny(finding[\"match\"], [\n  `^(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]{0,5}[^\"'\\x60\\r\\n]*[.,][A-Za-z_][A-Za-z0-9_-]*=`\n]);\nlet isEncryptedValue = filter.matchesAny(finding[\"secret\"], [\n  // Serialized encryption envelopes and armored ciphertext.\n  `(?i)^ENC\\[[A-Z0-9][A-Z0-9_.+/-]*(?:,|\\]|$)`,\n  `(?i)^ENC\\([A-Z0-9+/=_:.,-]{8,}\\)$`,\n  `(?i)^\\{cipher\\}.{4,}$`,\n  `^\\$ANSIBLE_VAULT(?:;|$)`,\n  `(?i)^!vault$`,\n  `^age-encryption\\.org/v[0-9]+$`,\n  `^-----BEGIN (?:AGE ENCRYPTED FILE|PGP MESSAGE|ENCRYPTED PRIVATE KEY)-----$`,\n  // OpenSSL salted output, HashiCorp Vault transit ciphertext, and Fernet.\n  `^U2FsdGVkX1[A-Za-z0-9+/=]{8,}$`,\n  `^vault:v[0-9]+:[A-Za-z0-9+/=_-]{8,}$`,\n  `^gAAAAA[A-Za-z0-9_-]{70,}={0,2}$`,\n  // Compact JWE and encrypted PASETO (local-purpose) tokens.\n  `^[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}$`,\n  `^v[124]\\.local\\.[A-Za-z0-9_-]{32,}(?:\\.[A-Za-z0-9_-]+)?$`,\n  // Windows DPAPI blobs in Base64 or exported SecureString hex form.\n  `^AQAAANCMnd8BFdERjHoAwE/Cl\\+sBA[A-Za-z0-9+/=]{16,}$`,\n  `(?i)^01000000d08c9ddf0115d1118c7a00c04fc297eb01[0-9a-f]{16,}$`\n]);\nlet isCryptographicAlgorithm = filter.matchesAny(finding[\"secret\"], [\n  // Common block ciphers with key sizes and/or modes.\n  `(?i)^(?:AES|RIJNDAEL|ARIA|CAMELLIA)[-_/]?(?:128|192|256)(?:[-_/](?:ECB|CBC(?:[-_/]HMAC[-_/]SHA[-_]?(?:256|384|512))?|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM|GMAC|EAX|OCB|SIV|GCM[-_]?SIV|XTS|KW|KWP))?$`,\n  `(?i)^(?:AES|RIJNDAEL|ARIA|CAMELLIA)[-_/]?(?:ECB|CBC|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM|GMAC|EAX|OCB|SIV|GCM[-_]?SIV|XTS|KW|KWP)$`,\n  `(?i)^(?:(?:RIJNDAEL|ARIA|CAMELLIA|DES(?:[-_]?(?:EDE3?|3|X))?|DESEDE|3DES|TRIPLE[-_]?DES|BLOWFISH|BF|TWOFISH|SERPENT|CAST(?:5|128|256)?|IDEA|SEED|SM4|RC[2456]|ARCFOUR)[-_/](?:ECB|CBC|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM|GMAC|EAX|OCB|SIV|GCM[-_]?SIV|XTS|KW|KWP)|X?(?:CHACHA20|SALSA20)[-_/]POLY1305|AESWRAP(?:[-_]?(?:128|192|256))?|DESEDEWRAP)$`,\n  // Java Cryptography Architecture transformations and PBE names.\n  `(?i)^(?:AES(?:[-_]?(?:128|192|256))?|ARIA(?:[-_]?(?:128|192|256))?|CAMELLIA(?:[-_]?(?:128|192|256))?|BLOWFISH|DES|DESEDE|RC2|RSA)/(?:ECB|CBC|PCBC|CFB(?:8|64|128)?|OFB(?:8|64|128)?|CTR|CTS|CCM|GCM)/(?:NO|PKCS[157]|ISO10126|OAEPWITH(?:MD5|SHA[-_]?(?:1|224|256|384|512))ANDMGF1)PADDING$`,\n  `(?i)^PBEWITH(?:HMAC)?(?:MD5|SHA(?:1|224|256|384|512))AND(?:AES(?:[-_]?(?:128|256))?|DES(?:EDE)?|TRIPLEDES|RC[24](?:[-_]?(?:40|128))?)$`,\n  // JOSE/JWE key-management and content-encryption identifiers.\n  `(?i)^(?:RSA1_5|RSA-OAEP(?:-(?:256|384|512))?|ECDH-ES(?:\\+A(?:128|192|256)(?:GCM)?KW)?|A(?:128|192|256)(?:KW|GCMKW|GCM|CBC-HS(?:256|384|512))|PBES2-HS(?:256|384|512)\\+A(?:128|192|256)KW)$`,\n  // Other explicit asymmetric encryption and key-wrapping descriptors.\n  `(?i)^(?:RSA(?:ES)?[-_/](?:OAEP(?:[-_/](?:MD5|SHA[-_]?(?:1|224|256|384|512)))?|PKCS1(?:[-_]?V?1[_.]5)?|NO[-_]?PADDING)|ECIES(?:[-_/](?:P(?:256|384|521)|SECP(?:256K1|256R1|384R1|521R1)))?|ELGAMAL[-_/](?:ECB|OAEP|PKCS1)|SM2[-_/](?:C1C2C3|C1C3C2))$`,\n  // Composite hash, MAC, signature, and password-derivation identifiers.\n  `(?i)^(?:HMAC[-_]?(?:MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512))|PBKDF2[-_/](?:HMAC[-_]?)?(?:SHA[-_]?(?:1|224|256|384|512))|HKDF[-_/]SHA[-_]?(?:1|224|256|384|512)|(?:RSA|DSA|ECDSA|ED25519)[-_/](?:MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512))|(?:MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512))[-_/](?:RSA|DSA|ECDSA|ED25519))$`,\n  // TLS and OpenSSH cipher-suite identifiers.\n  `(?i)^TLS_(?:(?:AES_(?:128|256)_GCM|CHACHA20_POLY1305)_SHA(?:256|384)|[A-Z0-9]+(?:_[A-Z0-9]+)*_WITH_[A-Z0-9]+(?:_[A-Z0-9]+)*)$`,\n  `(?i)^(?:AES(?:128|192|256)-(?:CBC|CTR|GCM)|CHACHA20-POLY1305)@OPENSSH\\.COM$`\n]);\nlet isContextualAlgorithmName = hasNonPlaintextPasswordContext && filter.matchesAny(finding[\"secret\"], [\n  // A field name can disambiguate an exact algorithm name, but cannot by\n  // itself prove that an arbitrary value is encrypted or hashed.\n  `(?i)^(?:AES|RIJNDAEL|ARIA|CAMELLIA|CHACHA20|XCHACHA20|SALSA20|XSALSA20|DES|DESEDE|3DES|TRIPLE[-_]?DES|TWOFISH|SERPENT|CAST(?:5|128|256)|IDEA|SEED|SM4|RC[2456]|ARCFOUR|RSA|ECIES|ELGAMAL|SM2|MD5|SHA[-_]?(?:1|224|256|384|512)|SHA3[-_]?(?:224|256|384|512)|BLAKE2[BS](?:[-_]?(?:256|512))?|BLAKE3|RIPEMD[-_]?(?:128|160|256|320)|WHIRLPOOL|SM3|PBKDF2|SCRYPT|BCRYPT|ARGON2(?:D|I|ID)?|HKDF|YESCRYPT)$`\n]);\nlet level = (\n  (\n    isDirectAuthArgument\n    || (hasAuthContext && hasIdentityFieldContext)\n  )\n  && !isCommented\n  && !isInstructionalPlaceholder\n) ? \"medium\" : \"low\";\nlet _ = filter.setConfidence(level);\n\nfilter.matchesAny(finding[\"secret\"], [\n  `^\\*+$`,\n  `^\\.+$`,\n  `(?i)^x{4,}$`,\n  `(?i)^\\[?(?:redacted|masked|filtered)\\]?$`,\n  `^\xe2\x80\xa2+$`,\n  `^\\$\\{.*}$`,\n  `^\\$\\([^\\r\\n]+\\)$`,\n  `^#\\{[^}\\r\\n]+}$`,\n  `^\\{\\{[ \\t]*.+[ \\t]*}}$`,\n  `^%\\{[^}]+}$`,\n  `^\\$[A-Za-z_][A-Za-z0-9_]*$`,\n  `(?i)^\\$env:[A-Za-z_][A-Za-z0-9_]*$`,\n  `^%[A-Za-z_][A-Za-z0-9_]*%$`,\n  `^<[^>]+>$`,\n  `^<[^>\\s]+$`,\n  `^\\{[^}]+}$`,\n  `(?i)^(?:your[_-]?password|placeholder|forbidden_value)$`,\n  `^\\([A-Za-z_][A-Za-z0-9_.]*(?:[ \\t]+[A-Za-z_][A-Za-z0-9_.]*)*\\)$`,\n  `^\\$\\(`,\n  `(?:\\$\\{|#\\{|\\{\\{|%\\{)`,\n  `%\\([A-Za-z_][A-Za-z0-9_]*\\)[#0 +\\-]?[0-9.]*(?:[diouxXeEfFgGcrs%])`,\n  `(?i)^--?passw(?:or)?d$`,\n  `^\\$2[abxy]\\$[0-9]{2}\\$[./A-Za-z0-9]{7,}$`,\n  `(?i)^\\$pbkdf2[-_][^$]+\\$.*$`,\n  `(?i)^(?:pbkdf2_(?:sha1|sha256)|bcrypt_sha256|argon2|scrypt|sha1|md5|crypt)\\$`,\n  `(?i)^\\$(?:1|5|6|7|y|gy|argon2(?:d|i|id)|scrypt|pbkdf2(?:[-_]sha(?:1|224|256|384|512))?|apr1)\\$`,\n  `^\\$[PH]\\$[./A-Za-z0-9]{20,}$`,\n  `(?i)^\\{(?:SSHA(?:256|384|512)?|SHA(?:256|384|512)?|MD5|CRYPT|BCRYPT|PBKDF2)}`,\n  `(?i)^SCRAM-SHA-(?:1|256|512)\\$`,\n  `(?i)^md5[0-9a-f]{32}$`,\n  `^\\*[0-9A-F]{40}$`\n])\n|| isEncryptedValue\n|| isCryptographicAlgorithm\n|| isContextualAlgorithmName\n|| isUnquotedCodeValue\n|| isUnquotedExpression\n|| hasNestedUnquotedAssignment\n|| filter.matchesAny(finding[\"match\"], [\n  `^(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?i:nil|null|none|undefined|true|false|string|str|text|integer|int|number|boolean|bool|object)(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`,\n  `^(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?:[$@][A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|:[A-Za-z_][A-Za-z0-9_]*|(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*::[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*|(?i:process\\.env|config|settings|credentials?|secrets?|var|local|module|data)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\])+|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*(?:\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*\\.(?i:(?:[a-z0-9]+_)*(?:passw(?:or)?d|psw|token|secret|hex)))[)}\\]]*\\\\?(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`\n])"

    strings:
        $secret = /(?:(?:[pP][aA][sS][sS][wW](?:[oO][rR])?[dD]|[pP][sS][wW]|[_.-][pP][wW])\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]{0,5}(?:"((?:\\.|[^"\\\r\n]){5,250})"|'((?:\\.|[^'\\\r\n]){5,250})'|\x60((?:\\.|[^\x60\\\r\n]){5,250})\x60|([^:=\s'"\x60,;][^\s'"\x60,;]{4,249}))(?:[ \t]*[,;)\}\]\r\n]|[ \t]+(?:#|\/\/|\/\*|--)|[ \t]*$|\\[NRnr])|\b(?:[lL][oO][gG][iI][nN]|[lL][oO][gG]_[iI][nN]|[aA][uU][tT][hH][eE][nN][tT][iI][cC][aA][tT][eE])\b[ \t]*\([ \t]*[^,()\r\n]{1,250}[ \t]*,[ \t]*(?:"((?:\\.|[^"\\\r\n]){4,250})"|'((?:\\.|[^'\\\r\n]){4,250})'|\x60((?:\\.|[^\x60\\\r\n]){4,250})\x60)[ \t]*\))/  // gitleaks:allow

    condition:
        $secret
}
