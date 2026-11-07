// betterleaks v1.10.0's gitlab-session-cookie rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GitlabSessionCookie
{
    meta:
        description     = "Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabSessionCookie"
        severity        = "high"
        score           = 80
        id              = "gitlab-session-cookie"
        confidence      = "high"
        keyword         = "_gitlab_session="
        skip_entropy_le = "3.0"

    strings:
        $secret = /_gitlab_session=[0-9a-z]{32}/  // gitleaks:allow

    condition:
        $secret
}
