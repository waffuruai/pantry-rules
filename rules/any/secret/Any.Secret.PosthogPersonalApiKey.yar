// betterleaks v1.10.0's posthog-personal-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PosthogPersonalApiKey
{
    meta:
        description     = "Detected a PostHog Personal API Key, which may expose administrative access to PostHog analytics projects."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PosthogPersonalApiKey"
        severity        = "high"
        score           = 80
        id              = "posthog-personal-api-key"
        confidence      = "high"
        keyword         = "phx_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b([pP][hH][xX]_[A-Za-za-zA-Z0-9_\-]{41,49})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
