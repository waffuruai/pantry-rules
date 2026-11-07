// betterleaks v1.10.0's openweather-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_OpenweatherApiKey
{
    meta:
        description         = "OpenWeather API key."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "OpenweatherApiKey"
        severity            = "medium"
        score               = 50
        id                  = "openweather-api-key"
        confidence          = "medium"
        keyword             = "openweather"
        keyword             = "pyowm"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:(?:[oO][pP][eE][nN][wW][eE][aA][tT][hH][eE][rR]|[pP][yY][oO][wW][mM])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
