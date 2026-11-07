// betterleaks v1.10.0's supabase-management-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SupabaseManagementToken
{
    meta:
        description     = "Detected a Supabase Management Token, which may allow unauthorized access to Supabase organizations and projects."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SupabaseManagementToken"
        severity        = "high"
        score           = 80
        id              = "supabase-management-token"
        confidence      = "high"
        keyword         = "sbp_"
        skip_entropy_le = "3.5"
        require_secret  = "^sbp_[a-z0-9_-]*[0-9][a-z0-9_-]*[0-9][a-z0-9_-]*$"  // gitleaks:allow

    strings:
        $secret = /\b(sbp_[a-z0-9_-]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
