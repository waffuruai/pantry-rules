// betterleaks v1.10.0's mailchimp-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_MailchimpApiKey
{
    meta:
        description = "Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "MailchimpApiKey"
        severity    = "high"
        score       = 80
        id          = "mailchimp-api-key"
        confidence  = "high"
        keyword     = "mailchimp"

    strings:
        $secret = /(?:[Mm][aA][iI][lL][cC][hH][iI][mM][pP][Ss][Dd][Kk].[iI][nN][iI][tT][iI][aA][lL][iI][zZ][eE]|[mM][aA][iI][lL][cC][hH][iI][mM][pP])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{32}-[uU][sS]\d\d)(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
