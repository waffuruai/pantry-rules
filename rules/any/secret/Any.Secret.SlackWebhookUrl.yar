// betterleaks v1.10.0's slack-webhook-url rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SlackWebhookUrl
{
    meta:
        description = "Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "SlackWebhookUrl"
        severity    = "high"
        score       = 80
        id          = "slack-webhook-url"
        confidence  = "high"
        keyword     = "hooks.slack.com"

    strings:
        $secret = /(?:https?:\/\/)?hooks.slack.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+\/]{43,56}/  // gitleaks:allow

    condition:
        $secret
}
