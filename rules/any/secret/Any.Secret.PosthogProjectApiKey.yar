// betterleaks v1.10.0's posthog-project-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PosthogProjectApiKey
{
    meta:
        description     = "Detected a PostHog Project API Key, a public write-only token used to send events to a PostHog project."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PosthogProjectApiKey"
        severity        = "high"
        score           = 80
        id              = "posthog-project-api-key"
        confidence      = "high"
        keyword         = "phc_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b([pP][hH][cC]_[A-Za-za-zA-Z0-9_\-]{41,44})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
