// betterleaks v1.10.0's cloudinary-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_CloudinaryApiKey
{
    meta:
        description     = "Detected a Cloudinary API key, used as a component of the cloudinary-api-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "CloudinaryApiKey"
        severity        = "high"
        score           = 80
        id              = "cloudinary-api-key"
        confidence      = "high"
        keyword         = "cloudinary"
        skip_entropy_lt = "2.75"

    strings:
        $secret = /\b[cC][lL][oO][uU][dD][iI][nN][aA][rR][yY](?:.|[\n\r]){0,32}?(?:[Aa][Pp][Ii][_\s]?[Kk][Ee][Yy]|[Kk][Ee][Yy])(?:.|[\n\r]){0,16}?\b([0-9]{15})\b/  // gitleaks:allow

    condition:
        $secret
}
