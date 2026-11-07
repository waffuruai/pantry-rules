// betterleaks v1.10.0's maxmind-license-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_MaxmindLicenseKey
{
    meta:
        description     = "Discovered a potential MaxMind license key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "MaxmindLicenseKey"
        severity        = "high"
        score           = 80
        id              = "maxmind-license-key"
        confidence      = "high"
        keyword         = "_mmk"
        skip_entropy_le = "4.0"

    strings:
        $secret = /\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
