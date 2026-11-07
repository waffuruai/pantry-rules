// betterleaks v1.10.0's mongodb-connection-string rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_MongodbConnectionString
{
    meta:
        description       = "Detected a MongoDB connection string with embedded credentials, potentially exposing direct database access and sensitive application data."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "MongodbConnectionString"
        severity          = "high"
        score             = 80
        id                = "mongodb-connection-string"
        confidence        = "high"
        keyword           = "mongodb://"
        keyword           = "mongodb+srv://"
        skip_entropy_le   = "4.0"
        skip_regex_secret = "(?i)\\bmongodb(?:\\+srv)?:\\/\\/(?:user(?:name)?|foo):(?:pass(?:word)?|bar)(?:[^@\\/]*)?@"  // gitleaks:allow
        skip_regex_secret = "(?i)\\bmongodb(?:\\+srv)?:\\/\\/[^\\s'\"\\x60]*(?:\\$\\{\\{[^}]+}}|\\$\\{[^}]+}|\\$[A-Za-z_][A-Za-z0-9_]*|{{[^}]+}}|<[^>]+>|\\[[^]]+])[^\\s'\"\\x60]*"  // gitleaks:allow

    strings:
        $secret = /\b(mongodb(?:\+srv)?:\/\/([!-9;-~]{3,50}):([!-?A-~]{3,88})@((?:[a-zA-Z0-9][\w.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?(?:,(?:[a-zA-Z0-9][\w.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?)*)\/?(?:([\w-]+)?(\?\w+=[\w@\/.$-]+(?:&(?:amp;)?\w+=[\w@\/.$-]+)*)?)?)(?:['"\s;\x60]|\\[nr]|\b|$)/  // gitleaks:allow

    condition:
        $secret
}
