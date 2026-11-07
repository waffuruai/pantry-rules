// betterleaks v1.10.0's slack-config-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SlackConfigAccessToken
{
    meta:
        description     = "Found a Slack Configuration access token, posing a risk to workspace configuration and sensitive data access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SlackConfigAccessToken"
        severity        = "high"
        score           = 80
        id              = "slack-config-access-token"
        confidence      = "high"
        keyword         = "xoxe.xoxb-"
        keyword         = "xoxe.xoxp-"
        skip_entropy_le = "2.0"

    strings:
        $secret = /[xX][oO][xX][eE].[xX][oO][xX][BPbp]-\d-[a-zA-Z0-9]{163,166}/  // gitleaks:allow

    condition:
        $secret
}
