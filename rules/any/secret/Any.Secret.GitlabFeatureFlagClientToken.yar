// betterleaks v1.10.0's gitlab-feature-flag-client-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GitlabFeatureFlagClientToken
{
    meta:
        description     = "Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabFeatureFlagClientToken"
        severity        = "high"
        score           = 80
        id              = "gitlab-feature-flag-client-token"
        confidence      = "high"
        keyword         = "glffct-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /glffct-[0-9a-zA-Z_\-]{20}/  // gitleaks:allow

    condition:
        $secret
}
