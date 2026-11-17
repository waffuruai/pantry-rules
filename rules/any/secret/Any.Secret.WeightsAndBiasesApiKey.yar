// betterleaks v1.10.0's weights-and-biases-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_WeightsAndBiasesApiKey
{
    meta:
        description         = "Detected a Weights & Biases API Key, which may expose ML experiment tracking and model registry access to unauthorized parties."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "WeightsAndBiasesApiKey"
        severity            = "medium"
        score               = 50
        id                  = "weights-and-biases-api-key"
        confidence          = "medium"
        keyword             = "wandb"
        keyword             = "weightsandbiases"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[wW][aA][nN][dD][bB]|[wW][eE][iI][gG][hH][tT][sS][aA][nN][dD][bB][iI][aA][sS][eE][sS])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
