// betterleaks v1.10.0's polymarket-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PolymarketApiKey
{
    meta:
        description       = "Identified a Polymarket API key, potentially compromising access to the Polymarket trading platform."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "PolymarketApiKey"
        severity          = "high"
        score             = 80
        id                = "polymarket-api-key"
        confidence        = "high"
        keyword           = "poly"
        component1        = "polymarket-api-secret"
        component1_within = "20L"
        component2        = "polymarket-passphrase"
        component2_within = "20L"
        skip_entropy_le   = "3.0"

    strings:
        $secret = /(?:(?:[pP][oO][lL][yY].{0,20}[kK][eE][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
