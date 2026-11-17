// betterleaks v1.10.0's twilio-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_TwilioApiKey
{
    meta:
        description     = "Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "TwilioApiKey"
        severity        = "high"
        score           = 80
        id              = "twilio-api-key"
        confidence      = "high"
        keyword         = "twilio"
        skip_entropy_le = "3.0"

    strings:
        $secret = /SK[0-9a-fA-F]{32}/  // gitleaks:allow

    condition:
        $secret
}
