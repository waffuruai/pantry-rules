// betterleaks v1.10.0's pkcs12-file rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_Pkcs12File
{
    meta:
        description = "Found a PKCS #12 file, which commonly contain bundled private keys."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "Pkcs12File"
        severity    = "high"
        score       = 80
        id          = "pkcs12-file"
        confidence  = "high"

    condition:
        filepath matches /(?:^|\/)[^\/]+\.[pP](?:12|[fF][xX])$/
}
