// betterleaks v1.10.0's yandex-aws-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_YandexAwsAccessToken
{
    meta:
        description = "Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "YandexAwsAccessToken"
        severity    = "high"
        score       = 80
        id          = "yandex-aws-access-token"
        confidence  = "high"
        keyword     = "yandex"

    strings:
        $secret = /(?:[yY][aA][nN][dD][eE][xX])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([Yy][Cc][A-Za-za-zA-Z0-9_\-]{38})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
