// betterleaks v1.10.0's adobe-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_AdobeClientSecret
{
    meta:
        description     = "Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AdobeClientSecret"
        severity        = "high"
        score           = 80
        id              = "adobe-client-secret"
        confidence      = "high"
        keyword         = "p8e-"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(p8e-[A-Za-z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
