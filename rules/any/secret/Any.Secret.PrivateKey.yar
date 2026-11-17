// betterleaks v1.10.0's private-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PrivateKey
{
    meta:
        description = "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "PrivateKey"
        severity    = "high"
        score       = 80
        id          = "private-key"
        confidence  = "high"
        keyword     = "-----begin"

    strings:
        $secret = /-----[Bb][Ee][Gg][Ii][Nn][a-z A-Z0-9_-]{0,100}[Pp][Rr][Ii][Vv][Aa][Tt][Ee] [Kk][Ee][Yy](?: [Bb][Ll][Oo][Cc][Kk])?-----[\s\S-]{64,}?[Kk][Ee][Yy](?: [Bb][Ll][Oo][Cc][Kk])?-----/  // gitleaks:allow

    condition:
        $secret
}
