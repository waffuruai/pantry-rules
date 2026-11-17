// betterleaks v1.10.0's gitlab-scim-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GitlabScimToken
{
    meta:
        description     = "Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabScimToken"
        severity        = "high"
        score           = 80
        id              = "gitlab-scim-token"
        confidence      = "high"
        keyword         = "glsoat-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /glsoat-[0-9a-zA-Z_\-]{20}/  // gitleaks:allow

    condition:
        $secret
}
