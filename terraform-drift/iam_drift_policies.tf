# ============================================================
# Policies IAM encontradas fora do Terraform (drift detectado em 28/06/2026)
# Para importar: terraform import aws_iam_role_policy.<nome> security-scanner-role:<policy>
# ============================================================

resource "aws_iam_role_policy" "allow_read_github_deploy_token" {
  name = "AllowReadGithubDeployToken"
  role = "security-scanner-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = "arn:aws:secretsmanager:us-east-2:442042548551:secret:github-deploy-token*"
      }
    ]
  })
}

# terraform import aws_iam_role_policy.allow_read_github_deploy_token security-scanner-role:AllowReadGithubDeployToken


resource "aws_iam_role_policy" "allow_s3_db" {
  name = "AllowS3DB"
  role = "security-scanner-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::security-scanner-db-442042548551/db/*"
      }
    ]
  })
}

# terraform import aws_iam_role_policy.allow_s3_db security-scanner-role:AllowS3DB


resource "aws_iam_role_policy" "dynamodb_auth" {
  name = "security-scanner-dynamodb-auth"
  role = "security-scanner-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SessionsTable"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          "arn:aws:dynamodb:us-east-2:442042548551:table/security-scanner-sessions",
          "arn:aws:dynamodb:us-east-2:442042548551:table/security-scanner-sessions/index/*"
        ]
      },
      {
        Sid    = "UsersTable"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query"
        ]
        Resource = "arn:aws:dynamodb:us-east-2:442042548551:table/security-scanner-users"
      }
    ]
  })
}

# terraform import aws_iam_role_policy.dynamodb_auth security-scanner-role:security-scanner-dynamodb-auth
