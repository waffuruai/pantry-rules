// betterleaks v1.10.0's slack-session-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SlackSessionToken
{
    meta:
        description     = "Detected a Slack client session token (xoxc-), which provides full user-level API access when paired with a session cookie."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SlackSessionToken"
        severity        = "high"
        score           = 80
        id              = "slack-session-token"
        confidence      = "high"
        keyword         = "xoxc-"
        skip_entropy_le = "3.5"

    strings:
        $secret = /xoxc-\d{9,15}-\d{9,15}-\d{9,15}-[a-f0-9]{64}\b/  // gitleaks:allow

    condition:
        $secret
}
