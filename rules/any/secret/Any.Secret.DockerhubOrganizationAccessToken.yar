// betterleaks v1.10.0's dockerhub-organization-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DockerhubOrganizationAccessToken
{
    meta:
        description     = "Detected a Docker Hub organization access token, which may expose organization repositories."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DockerhubOrganizationAccessToken"
        severity        = "high"
        score           = 80
        id              = "dockerhub-organization-access-token"
        confidence      = "high"
        keyword         = "dckr_oat_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(dckr_oat_[A-Za-z0-9_-]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
