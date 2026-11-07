// betterleaks v1.10.0's cloudinary-cloud-name rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_CloudinaryCloudName
{
    meta:
        description = "Detected a Cloudinary cloud name, used as a component of the cloudinary-api-secret composite rule."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "CloudinaryCloudName"
        severity    = "high"
        score       = 80
        id          = "cloudinary-cloud-name"
        confidence  = "high"
        keyword     = "cloudinary"

    strings:
        $secret = /\b[cC][lL][oO][uU][dD][iI][nN][aA][rR][yY](?:.|[\n\r]){0,32}?(?:[Cc][Ll][Oo][Uu][Dd][_\s]?[Nn][Aa][Mm][Ee]|[Cc][Ll][Oo][Uu][Dd])(?:.|[\n\r]){0,16}?\b([A-Za-z0-9_-]{3,32})\b/  // gitleaks:allow

    condition:
        $secret
}
