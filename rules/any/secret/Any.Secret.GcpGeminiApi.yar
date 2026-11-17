// betterleaks v1.10.0's gcp-gemini-api rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GcpGeminiApi
{
    meta:
        description     = "Detected a Google Gemini API key, which may expose Gemini model access and usage to unauthorized parties."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GcpGeminiApi"
        severity        = "high"
        score           = 80
        id              = "gcp-gemini-api"
        confidence      = "high"
        keyword         = "aq.ab8rn6"
        skip_entropy_le = "4.0"

    strings:
        $secret = /\b(AQ\.Ab8RN6[A-Za-z0-9_-]{44})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
