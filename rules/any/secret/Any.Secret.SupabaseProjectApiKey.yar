// betterleaks v1.10.0's supabase-project-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SupabaseProjectApiKey
{
    meta:
        description     = "Detected a Supabase Project API Key, which may expose project data through Supabase APIs when paired with a project URL."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SupabaseProjectApiKey"
        severity        = "high"
        score           = 80
        id              = "supabase-project-api-key"
        confidence      = "high"
        keyword         = "sb_secret_"
        component1      = "supabase-project-url"
        skip_entropy_le = "4.0"

    strings:
        $secret = /\b(sb_secret_[A-Za-z0-9_-]{31})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
