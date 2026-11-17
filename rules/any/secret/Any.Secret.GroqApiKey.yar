// betterleaks v1.10.0's groq-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GroqApiKey
{
    meta:
        description     = "Identified a Groq API Key, which may expose high-speed AI inference services to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GroqApiKey"
        severity        = "high"
        score           = 80
        id              = "groq-api-key"
        confidence      = "high"
        keyword         = "gsk_"
        skip_entropy_le = "3.5"

    strings:
        $secret = /\b([gG][sS][kK]_[a-zA-Z0-9]{52})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
