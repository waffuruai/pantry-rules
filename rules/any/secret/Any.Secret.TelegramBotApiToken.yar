// betterleaks v1.10.0's telegram-bot-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_TelegramBotApiToken
{
    meta:
        description = "Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "TelegramBotApiToken"
        severity    = "high"
        score       = 80
        id          = "telegram-bot-api-token"
        confidence  = "high"
        keyword     = "telegr"

    strings:
        $secret = /(?:[tT][eE][lL][eE][gG][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{5,16}:(?:A)[A-Za-z0-9_\-]{34})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
