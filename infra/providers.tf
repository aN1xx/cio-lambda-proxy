provider "aws" {
  region = "eu-central-1"
  assume_role {
    role_arn = data.terraform_remote_state.infra.outputs.workspace_iam_role
  }
}
