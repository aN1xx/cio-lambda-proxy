resource "aws_lambda_function" "cio_lambda" {
  function_name    = "cio_lambda-${terraform.workspace}"
  role             = aws_iam_role.cio_lambda_role.arn
  filename         = "${path.module}/../lambda-package.zip"
  handler          = "cio_lambda_proxy.main.lambda_handler"
  runtime          = "python3.9"
  source_code_hash = filebase64sha256("${path.module}/../lambda-package.zip")
  timeout          = 15
  environment {
    variables = {
      VAULT_ADDR            = var.vault_addr
      VAULT_AUTH_PROVIDER   = "aws"
      VAULT_AUTH_ROLE       = var.vault_auth_role
      VAULT_SECRET_PATH     = var.vault_secret_path
      VAULT_LOG_LEVEL       = "debug"
      VAULT_SECRET_FILE     = "/tmp/vault_secrets"
    }
  }
  layers = var.vault_lambda_layer_arn != "" ? [var.vault_lambda_layer_arn] : []

  vpc_config {
    security_group_ids = [aws_security_group.lambda.id]
    subnet_ids         = data.terraform_remote_state.infra.outputs.private_subnets
  }
}

resource "aws_lambda_function_url" "cio_lambda_url" {
  function_name      = aws_lambda_function.cio_lambda.function_name
  authorization_type = "AWS_IAM"

  cors {
    allow_origins = ["*"]
    allow_methods = ["POST", "PUT", "GET"]
  }
}


resource "aws_cloudwatch_log_group" "cio_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.cio_lambda.function_name}"
  retention_in_days = 7
  lifecycle {
    prevent_destroy = false
  }
}
