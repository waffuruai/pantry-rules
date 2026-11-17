// betterleaks v1.10.0's anthropic-admin-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AnthropicAdminApiKey
{
    meta:
        description = "Detected an Anthropic Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "AnthropicAdminApiKey"
        severity    = "high"
        score       = 80
        id          = "anthropic-admin-api-key"
        confidence  = "high"
        keyword     = "sk-ant-admin01"

    strings:
        $secret = /\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
