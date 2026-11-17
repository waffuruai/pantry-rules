// betterleaks v1.10.0's mailgun-signing-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_MailgunSigningKey
{
    meta:
        description = "Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "MailgunSigningKey"
        severity    = "high"
        score       = 80
        id          = "mailgun-signing-key"
        confidence  = "high"
        keyword     = "mailgun"

    strings:
        $secret = /(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Ha-h0-9]{32}-[A-Ha-h0-9]{8}-[A-Ha-h0-9]{8})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
