// betterleaks v1.10.0's influxdb-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_InfluxdbApiToken
{
    meta:
        description         = "Detected an InfluxDB API token, which may allow unauthorized access to time-series data and InfluxDB organization resources."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "InfluxdbApiToken"
        severity            = "high"
        score               = 80
        id                  = "influxdb-api-token"
        confidence          = "high"
        keyword             = "influx"
        skip_entropy_lt     = "4.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:\b[iI][nN][fF][lL][uU][xX](?:[dD][bB])?\b(?:.|[\n\r]){0,64}?\b(?:[tT][oO][kK][eE][nN]|[aA][pP][iI][_-]?[kK][eE][yY])\b(?:.|[\n\r]){0,32}?)[=:"'\s]{1,8}([a-zA-ZA-Za-z0-9+\/=_-]{88,})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
