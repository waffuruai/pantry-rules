// betterleaks v1.10.0's gitlab-incoming-mail-address-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GitlabIncomingMailAddressToken
{
    meta:
        description     = "Identified a GitLab incoming mail token embedded in an email address, risking manipulation of data sent by mail."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabIncomingMailAddressToken"
        severity        = "high"
        score           = 80
        id              = "gitlab-incoming-mail-address-token"
        confidence      = "high"
        keyword         = "incoming+"
        specificity     = 50
        skip_entropy_le = "3.0"

    strings:
        $secret = /incoming\+(?:[A-Za-z0-9._-]+-)?\d+-([A-Za-z0-9_-]+)-(?:issue(?:-\d+)?|merge-request)@/  // gitleaks:allow

    condition:
        $secret
}
