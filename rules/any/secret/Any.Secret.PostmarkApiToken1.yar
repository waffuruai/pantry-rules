// betterleaks v1.10.0's postmark-api-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PostmarkApiToken1
{
    meta:
        description     = "Postmark server or account API token, which may allow access to email delivery and account configuration."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PostmarkApiToken1"
        severity        = "high"
        score           = 80
        id              = "postmark-api-token.1"
        confidence      = "high"
        keyword         = "postmark"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:[pP][oO][sS][tT][mM][aA][rR][kK])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
