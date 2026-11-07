// betterleaks v1.10.0's snowflake-programmatic-access-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SnowflakeProgrammaticAccessToken1
{
    meta:
        description         = "Snowflake programmatic access token."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "SnowflakeProgrammaticAccessToken1"
        severity            = "high"
        score               = 80
        id                  = "snowflake-programmatic-access-token.1"
        confidence          = "high"
        keyword             = "snowflake"
        keyword             = "sf_token"
        component1          = "snowflake-account-host.1"
        component1_within   = "30L"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:(?:(?:[sS][nN][oO][wW][fF][lL][aA][kK][eE][_. -]*(?:[pP][rR][oO][gG][rR][aA][mM][mM][aA][tT][iI][cC][_. -]*)?(?:[aA][cC][cC][eE][sS][sS][_. -]*)?[tT][oO][kK][eE][nN]|[sS][fF][_. -]*[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{100,500})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
