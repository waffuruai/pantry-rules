// betterleaks v1.10.0's slack-bot-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SlackBotToken
{
    meta:
        description     = "Identified a Slack Bot token, which may compromise bot integrations and communication channel security."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SlackBotToken"
        severity        = "high"
        score           = 80
        id              = "slack-bot-token"
        confidence      = "high"
        keyword         = "xoxb"
        skip_entropy_le = "3.0"

    strings:
        $secret = /xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/  // gitleaks:allow

    condition:
        $secret
}
