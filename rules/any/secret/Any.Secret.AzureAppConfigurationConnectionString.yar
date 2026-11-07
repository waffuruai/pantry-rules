// betterleaks v1.10.0's azure-app-configuration-connection-string rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AzureAppConfigurationConnectionString
{
    meta:
        description     = "Detected an Azure App Configuration connection string."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AzureAppConfigurationConnectionString"
        severity        = "high"
        score           = 80
        id              = "azure-app-configuration-connection-string"
        confidence      = "high"
        keyword         = "azconfig.io"
        keyword         = "endpoint="
        keyword         = "secret="
        secret_group    = 3
        skip_entropy_le = "3.5"

    strings:
        $secret = /[Ee][nN][dD][pP][oO][iI][nN][tT]=([hH][tT][tT][pP][sS]:\/\/[A-Za-z0-9-]+\.[aA][zZ][cC][oO][nN][fF][iI][gG]\.[iI][oO]);[Ii][dD]=([^;\s'"]{4,80});[Ss][eE][cC][rR][eE][tT]=([a-zA-ZA-Za-z0-9+\/]{36,100}={0,2})/  // gitleaks:allow

    condition:
        $secret
}
