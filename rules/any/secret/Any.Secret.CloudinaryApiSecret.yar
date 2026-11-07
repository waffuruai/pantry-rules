// betterleaks v1.10.0's cloudinary-api-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CloudinaryApiSecret
{
    meta:
        description         = "Detected a Cloudinary API secret, which may allow unauthorized access to Cloudinary media and account APIs when paired with a cloud name and API key."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "CloudinaryApiSecret"
        severity            = "high"
        score               = 80
        id                  = "cloudinary-api-secret"
        confidence          = "high"
        keyword             = "cloudinary"
        component1          = "cloudinary-api-key"
        component2          = "cloudinary-cloud-name"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b[cC][lL][oO][uU][dD][iI][nN][aA][rR][yY](?:.|[\n\r]){0,32}?(?:[Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee]|[Aa][Pp][Ii][_\s]?[Ss][Ee][Cc][Rr][Ee][Tt])(?:.|[\n\r]){0,32}?\b([a-zA-ZA-Za-z0-9]{32})\b/  // gitleaks:allow

    condition:
        $secret
}
