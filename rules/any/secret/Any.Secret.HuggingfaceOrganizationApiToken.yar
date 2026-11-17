// betterleaks v1.10.0's huggingface-organization-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_HuggingfaceOrganizationApiToken
{
    meta:
        description     = "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "HuggingfaceOrganizationApiToken"
        severity        = "high"
        score           = 80
        id              = "huggingface-organization-api-token"
        confidence      = "high"
        keyword         = "api_org_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b(api_org_(?:[A-Za-z]{34}))(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
