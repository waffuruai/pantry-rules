// betterleaks v1.10.0's freemius-secret-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_FreemiusSecretKey
{
    meta:
        description = "Detected a Freemius secret key, potentially exposing sensitive information."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "FreemiusSecretKey"
        severity    = "medium"
        score       = 50
        id          = "freemius-secret-key"
        confidence  = "medium"
        keyword     = "secret_key"

    strings:
        $secret = /["'][sS][eE][cC][rR][eE][tT]_[kK][eE][yY]["']\s*=>\s*["']([sS][kK]_[\S]{29})["']/  // gitleaks:allow

    condition:
        $secret and filepath matches /\.[pP][hH][pP]$/
}
