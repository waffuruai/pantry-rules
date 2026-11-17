// betterleaks v1.10.0's anthropic-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AnthropicApiKey
{
    meta:
        description = "Identified an Anthropic API Key, which may compromise AI assistant integrations and expose sensitive data to unauthorized access."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "AnthropicApiKey"
        severity    = "high"
        score       = 80
        id          = "anthropic-api-key"
        confidence  = "high"
        keyword     = "sk-ant-api03"

    strings:
        $secret = /\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
