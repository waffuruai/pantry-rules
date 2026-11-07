// betterleaks v1.10.0's slack-config-refresh-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SlackConfigRefreshToken
{
    meta:
        description     = "Discovered a Slack Configuration refresh token, potentially allowing prolonged unauthorized access to configuration settings."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SlackConfigRefreshToken"
        severity        = "high"
        score           = 80
        id              = "slack-config-refresh-token"
        confidence      = "high"
        keyword         = "xoxe-"
        skip_entropy_le = "2.0"

    strings:
        $secret = /[xX][oO][xX][eE]-\d-[a-zA-Z0-9]{146}/  // gitleaks:allow

    condition:
        $secret
}
