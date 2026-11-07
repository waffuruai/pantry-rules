// betterleaks v1.10.0's slack-legacy-bot-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SlackLegacyBotToken
{
    meta:
        description     = "Uncovered a Slack Legacy bot token, which could lead to compromised legacy bot operations and data exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SlackLegacyBotToken"
        severity        = "high"
        score           = 80
        id              = "slack-legacy-bot-token"
        confidence      = "high"
        keyword         = "xoxb"
        skip_entropy_le = "2.0"

    strings:
        $secret = /xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}/  // gitleaks:allow

    condition:
        $secret
}
