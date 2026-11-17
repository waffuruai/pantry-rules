// betterleaks v1.10.0's supabase-project-url rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_SupabaseProjectUrl
{
    meta:
        description     = "Detected a Supabase project URL, used as a component of the supabase-project-api-key composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SupabaseProjectUrl"
        severity        = "high"
        score           = 80
        id              = "supabase-project-url"
        confidence      = "high"
        keyword         = "supabase.co"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(https:\/\/[a-z0-9]{16,32}\.supabase\.co)\b/  // gitleaks:allow

    condition:
        $secret
}
