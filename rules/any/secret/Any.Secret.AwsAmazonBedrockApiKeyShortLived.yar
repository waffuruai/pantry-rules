// betterleaks v1.10.0's aws-amazon-bedrock-api-key-short-lived rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_AwsAmazonBedrockApiKeyShortLived
{
    meta:
        description     = "Identified a pattern that may indicate short-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage"
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AwsAmazonBedrockApiKeyShortLived"
        severity        = "high"
        score           = 80
        id              = "aws-amazon-bedrock-api-key-short-lived"
        confidence      = "high"
        keyword         = "bedrock-api-key-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t/  // gitleaks:allow

    condition:
        $secret
}
