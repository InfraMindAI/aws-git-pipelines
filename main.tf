# ----------------------------------------------------------------------------------------------------
# This module create templates to build projects, which source code lives in CodeCommit
# ----------------------------------------------------------------------------------------------------

provider "aws" {
  region = local.aws_region
}

terraform {
  backend "local" {
    path = "../../tf_state/ci/git-pipeline/terraform.tfstate"
  }
}

locals {
  /*
    Please add new CodeCommit repositories here, for example:
      pipelines = {
        app1 = {},
        app2 = {}
      }
  */
  pipelines = {}

  #constants
  branch                  = "master"
  aws_region              = "ca-central-1"
  aws_account_id          = "1234567890" #add your AWS account id here
  path_to_build_scripts   = "git_pipelines/${local.build_scripts_filename}"
  build_scripts_filename  = "build_scripts.zip"
  codebuild_project_name  = "git-codebuild-project"
  lambda_function_name    = "GitPipelinesAutomation"
  path_to_lambda_handler  = "git_pipelines/${local.lambda_handler_filename}"
  lambda_handler_filename = "lambda_handler.zip"

  #read from state of other modules
  vpc_id               = data.terraform_remote_state.vpc.outputs.vpc_id
  subnet_ids           = data.terraform_remote_state.vpc.outputs.private_subnet_ids
  build_bucket         = data.terraform_remote_state.common_resources.outputs.build_bucket_name
  build_bucket_arn     = "arn:aws:s3:::${local.build_bucket}"
  ecr_repository_url   = data.terraform_remote_state.ecr.outputs.repository_url
  artifacts_bucket_arn = "arn:aws:s3:::${data.terraform_remote_state.common_resources.outputs.artifacts_bucket_name}"
}

# ----------------------------------------------------------------------------------------------------
# DATA
# ----------------------------------------------------------------------------------------------------

data "terraform_remote_state" "vpc" {
  backend = "local"

  config = {
    path = "../../tf_state/vpc/terraform.tfstate"
  }
}

data "terraform_remote_state" "common_resources" {
  backend = "local"

  config = {
    path = "../../tf_state/ci/common_resources/terraform.tfstate"
  }
}

data "terraform_remote_state" "ecr" {
  backend = "local"

  config = {
    path = "../../tf_state/ci/ecr/terraform.tfstate"
  }
}

# ----------------------------------------------------------------------------------------------------
# CODEPIPELINE for master, pipelines for brunches will be created by Lambda function
# ----------------------------------------------------------------------------------------------------

resource "aws_codepipeline" "pipelines" {
  for_each = local.pipelines

  name     = "git-${each.key}-${local.branch}"
  role_arn = aws_iam_role.codepipeline.arn

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "S3"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = {
        S3Bucket             = local.build_bucket
        S3ObjectKey          = local.path_to_build_scripts,
        PollForSourceChanges = false
      }
    }
  }

  stage {
    name = "Build"

    action {
      name            = "Build"
      category        = "Build"
      owner           = "AWS"
      provider        = "CodeBuild"
      input_artifacts = ["source_output"]
      version         = "1"

      configuration = {
        ProjectName = local.codebuild_project_name
        EnvironmentVariables = jsonencode([
          {
            name  = "REPOSITORY_NAME"
            value = each.key
            type  = "PLAINTEXT"
          },
          {
            name  = "BRANCH_NAME"
            value = local.branch
            type  = "PLAINTEXT"
          }
        ])
      }
    }
  }

  artifact_store {
    type     = "S3"
    location = local.build_bucket
  }
}

# ----------------------------------------------------------------------------------------------------
# CODEBUILD PROJECT
# ----------------------------------------------------------------------------------------------------

resource "aws_codebuild_project" "project" {
  name          = local.codebuild_project_name
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 30

  source {
    type      = "CODEPIPELINE"
    buildspec = "buildspec.yml"
  }

  environment {
    type                        = "LINUX_CONTAINER"
    image                       = "${local.ecr_repository_url}:latest"
    compute_type                = "BUILD_GENERAL1_SMALL"
    privileged_mode             = true
    image_pull_credentials_type = "SERVICE_ROLE"
  }

  vpc_config {
    vpc_id             = local.vpc_id
    subnets            = local.subnet_ids
    security_group_ids = [aws_security_group.codebuild.id]
  }

  artifacts {
    type = "CODEPIPELINE"
  }

  cache {
    type  = "LOCAL"
    modes = ["LOCAL_DOCKER_LAYER_CACHE"]
  }
}

resource "aws_s3_bucket_object" "build_scripts" {
  bucket = local.build_bucket
  key    = local.path_to_build_scripts
  source = local.build_scripts_filename
}

# ----------------------------------------------------------------------------------------------------
# CODEPIPELINE IAM ROLE
# ----------------------------------------------------------------------------------------------------

resource "aws_iam_role" "codepipeline" {
  name               = "git-codepipeline-role"
  assume_role_policy = data.aws_iam_policy_document.codepipeline_assume_policy.json
}

data "aws_iam_policy_document" "codepipeline_assume_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codepipeline.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "codepipeline" {
  role       = aws_iam_role.codepipeline.name
  policy_arn = aws_iam_policy.codepipeline.arn
}

resource "aws_iam_policy" "codepipeline" {
  name   = "git-codepipeline-policy"
  policy = data.aws_iam_policy_document.codepipeline.json
}

data "aws_iam_policy_document" "codepipeline" {

  //for downloading source in codepipeline source stage, and for saving artifacts
  statement {
    sid    = "S3Access"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetBucketVersioning"
    ]

    resources = [
      local.build_bucket_arn,
      "${local.build_bucket_arn}/*"
    ]
  }

  //for allowing CodePipeline to start build on CodeBuild
  statement {
    sid    = "CodeBuildAccess"
    effect = "Allow"

    actions = [
      "codebuild:StartBuild",
      "codebuild:BatchGetBuilds"
    ]

    resources = [
      "arn:aws:codebuild:${local.aws_region}:${local.aws_account_id}:project/${local.codebuild_project_name}"
    ]
  }
}

# ----------------------------------------------------------------------------------------------------
# CODEBUILD IAM ROLE
# ----------------------------------------------------------------------------------------------------

resource "aws_iam_role" "codebuild" {
  name               = "git-codebuild-role"
  assume_role_policy = data.aws_iam_policy_document.codebuild_assume_policy.json
}

data "aws_iam_policy_document" "codebuild_assume_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "codebuild" {
  role       = aws_iam_role.codebuild.name
  policy_arn = aws_iam_policy.codebuild.arn
}

resource "aws_iam_policy" "codebuild" {
  name   = "git-codebuild-policy"
  policy = data.aws_iam_policy_document.codebuild.json
}

data "aws_iam_policy_document" "codebuild" {

  //for getting project source from CodeCommit
  statement {
    effect = "Allow"

    actions = [
      "codecommit:Get*",
      "codecommit:BatchGet*",
      "codecommit:GitPull",
      "codecommit:List*",
      "codecommit:Describe*",
      "codecommit:BatchDescribe*"
    ]

    resources = [
      "arn:aws:codecommit:${local.aws_region}:${local.aws_account_id}:*"
    ]
  }

  //for saving logs to CloudWatch when building project
  statement {
    sid    = "CloudWatchAccess"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = [
      "arn:aws:logs:${local.aws_region}:${local.aws_account_id}:log-group:/aws/codebuild/${local.codebuild_project_name}",
      "arn:aws:logs:${local.aws_region}:${local.aws_account_id}:log-group:/aws/codebuild/${local.codebuild_project_name}:*"
    ]
  }

  //for setting up networking of EC2 server, on which project builds
  statement {
    sid    = "EC2Access1"
    effect = "Allow"

    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs"
    ]

    resources = ["*"]
  }

  //for setting up networking of EC2 server, on which project builds
  statement {
    sid    = "EC2Access2"
    effect = "Allow"

    actions = [
      "ec2:CreateNetworkInterfacePermission"
    ]

    resources = [
      "arn:aws:ec2:${local.aws_region}:${local.aws_account_id}:network-interface/*"
    ]
  }

  //for publishing/getting Docker images to/from ECR: log into ECR
  statement {
    sid    = "ECRAccess1"
    effect = "Allow"

    actions = [
      "ecr:GetAuthorizationToken"
    ]

    resources = [
      "*"
    ]
  }

  //for downloading custom build image & publishing Docker image to ECR
  statement {
    sid    = "ECRAccess2"
    effect = "Allow"

    actions = [
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage"
    ]

    resources = [
      "arn:aws:ecr:${local.aws_region}:${local.aws_account_id}:repository/*"
    ]
  }

  //for uploading to artifactory S3 bucket
  statement {
    sid    = "S3Access1"
    effect = "Allow"

    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${local.artifacts_bucket_arn}/*"
    ]
  }

  //for downloading source and uploading artifact
  statement {
    sid    = "S3Access2"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:GetObject"
    ]

    resources = [
      "${local.build_bucket_arn}/*"
    ]
  }

  #for publishing test reports
  statement {
    sid    = "ReportsAccess"
    effect = "Allow"

    actions = [
      "codebuild:CreateReportGroup",
      "codebuild:CreateReport",
      "codebuild:UpdateReport",
      "codebuild:BatchPutTestCases"
    ]

    resources = [
      "arn:aws:codebuild:${local.aws_region}:${local.aws_account_id}:report-group/${local.codebuild_project_name}-CiReports"
    ]
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Security Group
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_security_group" "codebuild" {
  name   = "git-codebuild-sg"
  vpc_id = local.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outgoing traffic."
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Create Lamdba function to start/create/delete CodePipelines
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_lambda_function" "function" {
  s3_bucket = local.build_bucket
  s3_key    = aws_s3_bucket_object.lambda_handler.key

  function_name = local.lambda_function_name
  role          = aws_iam_role.lambda_handler.arn
  handler       = "index.handler"
  runtime       = "nodejs10.x"
  description   = "CodeCommit event handler to create/start/delete CodePipelines"
  timeout       = 600
  memory_size   = 128
}

resource "aws_s3_bucket_object" "lambda_handler" {
  bucket = local.build_bucket
  key    = local.path_to_lambda_handler
  source = local.build_scripts_filename
}

# ---------------------------------------------------------------------------------------------------------------------
# Lambda function role and policy
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_role" "lambda_handler" {
  name               = local.lambda_function_name
  path               = "/lambda/ci/"
  assume_role_policy = data.aws_iam_policy_document.lambda_handler_assume_role_policy.json
}

data "aws_iam_policy_document" "lambda_handler_assume_role_policy" {
  statement {
    sid     = "assumeRolePolicy"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "lambda_codepipeline" {
  role       = aws_iam_role.lambda_handler.name
  policy_arn = aws_iam_policy.lambda_codepipeline.arn
}

resource "aws_iam_policy" "lambda_codepipeline" {
  name   = "${local.lambda_function_name}-codepipeline"
  policy = data.aws_iam_policy_document.lambda_policy.json
}

data "aws_iam_policy_document" "lambda_policy" {

  statement {
    sid    = "CodePipelineAccess"
    effect = "Allow"

    actions = [
      "codepipeline:CreatePipeline",
      "codepipeline:DeletePipeline",
      "codepipeline:StartPipelineExecution"
    ]

    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.codepipeline.arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["codepipeline.amazonaws.com"]
    }
  }

  statement {
    sid       = "CloudWatchLogAccess"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Setup CloudWatch Event Rule for Lambda function
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "codecommit" {
  name        = "${local.lambda_function_name}EventRule"
  description = "Event Rule to run ${local.lambda_function_name} on changes in CodeCommit repositories"
  event_pattern = templatefile("${path.module}/event_pattern.json.template", {
    repository_arns = [for repository_name, value in local.pipelines : "arn:aws:codecommit:${local.aws_region}:${local.aws_account_id}:${repository_name}"]
  })
}

resource "aws_cloudwatch_event_target" "target" {
  rule      = aws_cloudwatch_event_rule.codecommit.name
  target_id = "${local.lambda_function_name}EventRule"
  arn       = aws_lambda_function.function.arn
}

resource "aws_lambda_permission" "cloudwatch_lambda_permission" {
  action        = "lambda:InvokeFunction"
  function_name = local.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.codecommit.arn
}
