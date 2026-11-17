// betterleaks v1.10.0's mailgun-private-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_MailgunPrivateApiToken
{
    meta:
        description = "Found a Mailgun private API token, risking unauthorized email service operations and data breaches."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "MailgunPrivateApiToken"
        severity    = "high"
        score       = 80
        id          = "mailgun-private-api-token"
        confidence  = "high"
        keyword     = "mailgun"

    strings:
        $secret = /(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([kK][eE][yY]-[A-Fa-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
