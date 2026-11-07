// betterleaks v1.10.0's slack-legacy-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SlackLegacyToken
{
    meta:
        description     = "Detected a Slack Legacy token, risking unauthorized access to older Slack integrations and user data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SlackLegacyToken"
        severity        = "high"
        score           = 80
        id              = "slack-legacy-token"
        confidence      = "high"
        keyword         = "xoxo"
        keyword         = "xoxs"
        skip_entropy_le = "2.0"

    strings:
        $secret = /xox[os]-\d+-\d+-\d+-[a-fA-F\d]+/  // gitleaks:allow

    condition:
        $secret
}
