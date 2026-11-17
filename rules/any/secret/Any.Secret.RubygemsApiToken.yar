// betterleaks v1.10.0's rubygems-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_RubygemsApiToken
{
    meta:
        description     = "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "RubygemsApiToken"
        severity        = "high"
        score           = 80
        id              = "rubygems-api-token"
        confidence      = "high"
        keyword         = "rubygems_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b(rubygems_[a-f0-9]{48})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
