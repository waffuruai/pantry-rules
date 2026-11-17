// betterleaks v1.10.0's gitlab-feed-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GitlabFeedToken
{
    meta:
        description     = "Identified a GitLab feed token, risking exposure of user data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabFeedToken"
        severity        = "high"
        score           = 80
        id              = "gitlab-feed-token"
        confidence      = "high"
        keyword         = "glft-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /glft-[0-9a-zA-Z_\-]{20}/  // gitleaks:allow

    condition:
        $secret
}
