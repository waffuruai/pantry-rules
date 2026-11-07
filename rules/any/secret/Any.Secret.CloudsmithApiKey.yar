// betterleaks v1.10.0's cloudsmith-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CloudsmithApiKey
{
    meta:
        description = "Detected a Cloudsmith API key, which may expose package repositories and artifact management operations to unauthorized access."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "CloudsmithApiKey"
        severity    = "high"
        score       = 80
        id          = "cloudsmith-api-key"
        confidence  = "high"
        keyword     = "csa_"

    strings:
        $secret = /\b(csa_[a-f0-9]{30}[A-Za-z0-9]{6})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
