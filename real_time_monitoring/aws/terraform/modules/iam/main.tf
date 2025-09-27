

resource "aws_iam_role" "opa_server_ec2_role" {
    
    assume_role_policy = file("${path.module}/assume_role_policies/assume_role_for_ec2.json")
    
    name = var.rolenames
    

    
}

resource "aws_iam_role_policy_attachment" "administrator_policy_to_" {
    role = aws_iam_role.opa_server_ec2_role.name
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    
}

resource "aws_iam_instance_profile" "ec2rolle_instance_profile" {
    
    name = aws_iam_role.opa_server_ec2_role.name
    role = aws_iam_role.opa_server_ec2_role.name

  
}

resource "aws_iam_role" "lambda_roles_for_cspm" {
    for_each = var.lambda_role_with_their_policies
    name = each.key
    assume_role_policy = file("${path.module}/assume_role_policies/assume_role_for_lambda.json")
    
}

resource "aws_iam_policy" "lamba_policies" {
    for_each = var.lambda_role_with_their_policies
    name = each.value
    policy = file("${path.module}/iam_policies/${each.value}.json")
    
}


resource "aws_iam_role_policy_attachment" "lambda_roles" {
    depends_on = [ aws_iam_role.lambda_roles_for_cspm , aws_iam_policy.lamba_policies ]
    for_each = var.lambda_role_with_their_policies
    role = each.key
    policy_arn = "arn:aws:iam::${var.account_id}:policy/${each.value}"
  
}