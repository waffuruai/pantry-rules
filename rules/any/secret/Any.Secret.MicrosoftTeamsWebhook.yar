// betterleaks v1.10.0's microsoft-teams-webhook rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_MicrosoftTeamsWebhook
{
    meta:
        description = "Uncovered a Microsoft Teams Webhook, which could lead to unauthorized access to team collaboration tools and data leaks."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "MicrosoftTeamsWebhook"
        severity    = "high"
        score       = 80
        id          = "microsoft-teams-webhook"
        confidence  = "high"
        keyword     = "webhook.office.com"
        keyword     = "webhookb2"
        keyword     = "incomingwebhook"

    strings:
        $secret = /https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/  // gitleaks:allow

    condition:
        $secret
}
