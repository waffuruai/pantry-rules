// betterleaks v1.10.0's yandex-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_YandexAccessToken
{
    meta:
        description = "Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "YandexAccessToken"
        severity    = "high"
        score       = 80
        id          = "yandex-access-token"
        confidence  = "high"
        keyword     = "yandex"

    strings:
        $secret = /(?:[yY][aA][nN][dD][eE][xX])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([tT]1\.[a-zA-ZA-Z0-9a-z_-]+[=]{0,2}\.[a-zA-ZA-Z0-9a-z_-]{86}[=]{0,2})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
