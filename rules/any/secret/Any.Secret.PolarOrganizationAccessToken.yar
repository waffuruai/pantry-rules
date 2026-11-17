// betterleaks v1.10.0's polar-organization-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PolarOrganizationAccessToken
{
    meta:
        description     = "Polar organization access token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PolarOrganizationAccessToken"
        severity        = "high"
        score           = 80
        id              = "polar-organization-access-token"
        confidence      = "high"
        keyword         = "polar_oat_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(polar_oat_[A-Za-z0-9_-]{20,100})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
