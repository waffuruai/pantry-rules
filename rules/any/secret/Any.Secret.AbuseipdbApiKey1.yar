// betterleaks v1.10.0's abuseipdb-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AbuseipdbApiKey1
{
    meta:
        description     = "AbuseIPDB API key, which may allow access to IP reputation data and abuse-reporting APIs."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AbuseipdbApiKey1"
        severity        = "high"
        score           = 80
        id              = "abuseipdb-api-key.1"
        confidence      = "high"
        keyword         = "abuseipdb"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:[aA][bB][uU][sS][eE][iI][pP][dD][bB])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{80})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
