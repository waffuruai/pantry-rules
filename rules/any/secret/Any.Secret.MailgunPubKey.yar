// betterleaks v1.10.0's mailgun-pub-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_MailgunPubKey
{
    meta:
        description = "Discovered a Mailgun public validation key, which could expose email verification processes and associated data."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "MailgunPubKey"
        severity    = "high"
        score       = 80
        id          = "mailgun-pub-key"
        confidence  = "high"
        keyword     = "mailgun"

    strings:
        $secret = /(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([pP][uU][bB][kK][eE][yY]-[A-Fa-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
