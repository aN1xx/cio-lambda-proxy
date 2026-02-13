resource "aws_security_group" "lambda" {
  name        = "${local.project_name}-${terraform.workspace}-lambda"
  description = "${local.project_name}-${terraform.workspace}-lambda"
  vpc_id      = data.terraform_remote_state.infra.outputs.vpc

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Role = "lambda"
    Name = "${local.project_name}-${terraform.workspace}"
    Env  = terraform.workspace
  }

  egress {
    from_port = 443
    to_port   = 443
    protocol  = "TCP"

    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  egress {
      from_port = 8243
      protocol  = "TCP"
      to_port   = 8243

      cidr_blocks = [
      "0.0.0.0/0",]
  }
}
