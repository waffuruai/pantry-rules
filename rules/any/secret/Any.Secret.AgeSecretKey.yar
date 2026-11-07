// betterleaks v1.10.0's age-secret-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_AgeSecretKey
{
    meta:
        description = "Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "AgeSecretKey"
        severity    = "high"
        score       = 80
        id          = "age-secret-key"
        confidence  = "high"
        keyword     = "age-secret-key-1"

    strings:
        $secret = /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/  // gitleaks:allow

    condition:
        $secret
}
