// betterleaks v1.10.0's gocardless-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GocardlessApiToken
{
    meta:
        description     = "Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GocardlessApiToken"
        severity        = "high"
        score           = 80
        id              = "gocardless-api-token"
        confidence      = "high"
        keyword         = "live_"
        keyword         = "gocardless"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:[gG][oO][cC][aA][rR][dD][lL][eE][sS][sS])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([lL][iI][vV][eE]_[A-Za-z0-9\-_=]{40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
