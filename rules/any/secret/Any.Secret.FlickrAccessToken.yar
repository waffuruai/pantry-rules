// betterleaks v1.10.0's flickr-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_FlickrAccessToken
{
    meta:
        description         = "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "FlickrAccessToken"
        severity            = "high"
        score               = 80
        id                  = "flickr-access-token"
        confidence          = "high"
        keyword             = "flickr"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[fF][lL][iI][cC][kK][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
