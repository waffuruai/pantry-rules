// betterleaks v1.10.0's weights-and-biases-api-key-v1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_WeightsAndBiasesApiKeyV1
{
    meta:
        description         = "Detected a Weights & Biases v1 API Key (wandb_v1_), which may expose ML experiment tracking and artifact storage to unauthorized access."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "WeightsAndBiasesApiKeyV1"
        severity            = "high"
        score               = 80
        id                  = "weights-and-biases-api-key-v1"
        confidence          = "high"
        keyword             = "wandb_v1_"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b([wW][aA][nN][dD][bB]_[vV]1_[a-zA-ZA-Za-z0-9_]{77})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
