// betterleaks v1.10.0's slack-session-cookie rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SlackSessionCookie
{
    meta:
        description     = "Detected a Slack session cookie (xoxd-), which authenticates browser and desktop sessions across all of a user's workspaces."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SlackSessionCookie"
        severity        = "high"
        score           = 80
        id              = "slack-session-cookie"
        confidence      = "high"
        keyword         = "xoxd-"
        skip_entropy_le = "3.5"

    strings:
        $secret = /(xoxd-[\w\/\\+-]{100,}={0,2})(?:[^\w\/+=-]|$)/  // gitleaks:allow

    condition:
        $secret
}
