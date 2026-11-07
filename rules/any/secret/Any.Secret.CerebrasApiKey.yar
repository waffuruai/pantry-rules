// betterleaks v1.10.0's cerebras-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CerebrasApiKey
{
    meta:
        description     = "Identified a Cerebras AI API Key, which may expose AI inference services to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "CerebrasApiKey"
        severity        = "high"
        score           = 80
        id              = "cerebras-api-key"
        confidence      = "high"
        keyword         = "csk-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b([cC][sS][kK]-[A-Za-z0-9]{48})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
