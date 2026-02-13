resource "aws_iam_role" "cio_lambda_role" {
  name = "${local.project_name}-role-${terraform.workspace}"

  assume_role_policy = file("${path.module}/policies/lambda-role.json")
}

resource "aws_lambda_permission" "allow_api_gw_lambda" {
  statement_id  = "AllowLambdaAInvokeFromAPIGW"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cio_lambda.function_name
  principal     = "lambda.amazonaws.com"
  source_arn    = data.terraform_remote_state.api-gw-lambda.outputs.api_gw_lambda_arn
}

resource "aws_iam_role_policy_attachment" "cio_lambda_logs" {
  role       = aws_iam_role.cio_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "cio_lambda_vpc_execution_role" {
  role       = aws_iam_role.cio_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

data "template_file" "lambda-policy" {
  template = file("policies/lambda-policy.json")
}

resource "aws_iam_role_policy" "cio_lambda_policy" {
  name   = "${local.project_name}-${terraform.workspace}-public-api-gateway-lambda"
  policy = data.template_file.lambda-policy.rendered
  role   = aws_iam_role.cio_lambda_role.id
}

resource "aws_lambda_permission" "allow_invoke_url_from_other_lambda" {
  statement_id  = "AllowInvokeFromAPIGWLambda"
  action        = "lambda:InvokeFunctionUrl"
  function_name = aws_lambda_function.cio_lambda.function_name

  principal     = "lambda.amazonaws.com"
  source_arn    = data.terraform_remote_state.api-gw-lambda.outputs.api_gw_lambda_arn
}
