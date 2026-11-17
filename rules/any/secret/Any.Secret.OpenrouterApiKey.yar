// betterleaks v1.10.0's openrouter-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_OpenrouterApiKey
{
    meta:
        description     = "Detected an OpenRouter API Key, which may expose access to multiple AI models through the OpenRouter gateway."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "OpenrouterApiKey"
        severity        = "high"
        score           = 80
        id              = "openrouter-api-key"
        confidence      = "high"
        keyword         = "sk-or-v1-"
        skip_entropy_le = "3.5"

    strings:
        $secret = /\b([sS][kK]-[oO][rR]-[vV]1-[A-F0-9a-f]{64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
