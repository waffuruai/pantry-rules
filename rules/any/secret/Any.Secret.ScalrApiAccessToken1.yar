// betterleaks v1.10.0's scalr-api-access-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ScalrApiAccessToken1
{
    meta:
        description     = "Scalr API access token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ScalrApiAccessToken1"
        severity        = "high"
        score           = 80
        id              = "scalr-api-access-token.1"
        confidence      = "high"
        keyword         = "scalr"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:(?:[sS][cC][aA][lL][rR](?:[_. -]*(?:[aA][pP][iI]|[aA][cC][cC][eE][sS][sS]))?[_. -]*(?:[sS][eE][cC][rR][eE][tT]|[kK][eE][yY]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJ1c2VyIiwianRpIjoiYXQt[A-Za-z0-9_-]{20,40}\.[A-Za-z0-9_-]{43})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
