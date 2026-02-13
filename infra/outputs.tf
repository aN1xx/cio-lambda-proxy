output "cio_lambda_arn" {
  value       = aws_lambda_function.cio_lambda.arn
  description = "ARN of the CIO Lambda function"
}

output "cio_lambda_name" {
  value       = aws_lambda_function.cio_lambda.function_name
  description = "Function name of the CIO Lambda"
}

output "cio_lambda_function_url" {
  description = "Function URL for cio_lambda"
  value       = aws_lambda_function_url.cio_lambda_url.function_url
}
