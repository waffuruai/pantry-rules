// betterleaks v1.10.0's yandex-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_YandexApiKey
{
    meta:
        description = "Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "YandexApiKey"
        severity    = "high"
        score       = 80
        id          = "yandex-api-key"
        confidence  = "high"
        keyword     = "yandex"

    strings:
        $secret = /(?:[yY][aA][nN][dD][eE][xX])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([Aa][Qq][Vv][Nn][a-zA-ZA-Za-z0-9_\-]{35,38})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
