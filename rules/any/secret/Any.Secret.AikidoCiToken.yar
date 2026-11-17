// betterleaks v1.10.0's aikido-ci-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_AikidoCiToken
{
    meta:
        description     = "Detected an Aikido CI token, which may allow unauthorized CI scan integration activity in Aikido."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AikidoCiToken"
        severity        = "high"
        score           = 80
        id              = "aikido-ci-token"
        confidence      = "high"
        keyword         = "aik_ci_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(AIK_CI_[A-Za-z0-9]{20,44})\b/  // gitleaks:allow

    condition:
        $secret
}
