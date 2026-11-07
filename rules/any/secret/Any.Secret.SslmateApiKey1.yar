// betterleaks v1.10.0's sslmate-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SslmateApiKey1
{
    meta:
        description         = "SSLMate API key."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "SslmateApiKey1"
        severity            = "high"
        score               = 80
        id                  = "sslmate-api-key.1"
        confidence          = "high"
        keyword             = "sslmate"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:(?:[sS][sS][lL][mM][aA][tT][eE](?:[_. -]*(?:[aA][pP][iI]))?[_. -]*(?:[sS][eE][cC][rR][eE][tT]|[kK][eE][yY]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{36})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
