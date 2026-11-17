// betterleaks v1.10.0's gitlab-incoming-mail-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GitlabIncomingMailToken
{
    meta:
        description     = "Identified a GitLab incoming mail token, risking manipulation of data sent by mail."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabIncomingMailToken"
        severity        = "high"
        score           = 80
        id              = "gitlab-incoming-mail-token"
        confidence      = "high"
        keyword         = "glimt-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /glimt-[0-9a-zA-Z_\-]{25}/  // gitleaks:allow

    condition:
        $secret
}
