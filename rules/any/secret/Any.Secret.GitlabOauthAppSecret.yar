// betterleaks v1.10.0's gitlab-oauth-app-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GitlabOauthAppSecret
{
    meta:
        description     = "Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabOauthAppSecret"
        severity        = "high"
        score           = 80
        id              = "gitlab-oauth-app-secret"
        confidence      = "high"
        keyword         = "gloas-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /gloas-[0-9a-zA-Z_\-]{64}/  // gitleaks:allow

    condition:
        $secret
}
