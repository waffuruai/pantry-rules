// betterleaks v1.10.0's persona-production-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PersonaProductionApiKey
{
    meta:
        description     = "Persona production API key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PersonaProductionApiKey"
        severity        = "high"
        score           = 80
        id              = "persona-production-api-key"
        confidence      = "high"
        keyword         = "persona_production_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(persona_production_[a-z0-9_-]{20,80})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
