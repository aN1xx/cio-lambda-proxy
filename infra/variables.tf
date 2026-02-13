variable "vault_addr" {
  description = "HashiCorp Vault address"
  type        = string
  default     = "https://vault.example.com:8200/"
}

variable "vault_auth_role" {
  description = "Vault auth role name"
  type        = string
  default     = "cio-lambda-proxy"
}

variable "vault_secret_path" {
  description = "Vault secret path"
  type        = string
  default     = "secret/data/cio-lambda-proxy"
}

variable "vault_lambda_layer_arn" {
  description = "ARN of the Vault Lambda extension layer"
  type        = string
  default     = ""
}
