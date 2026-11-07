// betterleaks v1.10.0's slack-app-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SlackAppToken
{
    meta:
        description     = "Detected a Slack App-level token, risking unauthorized access to Slack applications and workspace data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SlackAppToken"
        severity        = "high"
        score           = 80
        id              = "slack-app-token"
        confidence      = "high"
        keyword         = "xapp"
        skip_entropy_le = "2.0"

    strings:
        $secret = /[xX][aA][pP][pP]-\d-[a-zA-Z0-9]+-\d+-[A-Za-z0-9]+/  // gitleaks:allow

    condition:
        $secret
}
