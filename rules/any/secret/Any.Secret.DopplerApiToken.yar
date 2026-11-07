// betterleaks v1.10.0's doppler-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DopplerApiToken
{
    meta:
        description     = "Discovered a Doppler API token, posing a risk to environment and secrets management security."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DopplerApiToken"
        severity        = "high"
        score           = 80
        id              = "doppler-api-token"
        confidence      = "high"
        keyword         = "dp.pt."
        skip_entropy_le = "2.0"

    strings:
        $secret = /dp\.pt\.[A-Za-z0-9]{43}/  // gitleaks:allow

    condition:
        $secret
}
