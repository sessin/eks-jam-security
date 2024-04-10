module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  #version = "~> 3.0"
  version = "5.1.1"

  name = local.name ## 모든 resource의 Name tag에 추가 됩니다.
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 10)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 100)]

  public_subnet_suffix  = "pub-sb"
  private_subnet_suffix = "priv-sb"

  enable_nat_gateway   = true
  create_igw           = true
  enable_dns_hostnames = true
  single_nat_gateway   = true

  manage_default_network_acl    = true
  default_network_acl_tags      = { Name = "${local.name}-default" }
  manage_default_route_table    = true
  default_route_table_tags      = { Name = "${local.name}-default" }
  manage_default_security_group = true
  default_security_group_tags   = { Name = "${local.name}-default" }


  ## subnet tagging for alb-controller
  private_subnet_tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
    "kubernetes.io/role/internal-elb"     = 1
  }
  public_subnet_tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
    "kubernetes.io/role/elb"              = 1
  }

  ## additional tags
  tags = local.tags

}

module "eks_blueprints" {
  source = "github.com/aws-ia/terraform-aws-eks-blueprints?ref=v4.32.1" # module version pinned. EKS blue print v5 does not provide backward comparibility

  cluster_name              = local.name
  vpc_id                    = module.vpc.vpc_id
  private_subnet_ids        = module.vpc.private_subnets
  cluster_version           = local.cluster_version
  cluster_enabled_log_types = []

  map_roles = [
    {
      rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/TeamRole"
      username = "ops-role"         # The user name within Kubernetes to map to the IAM role
      groups   = ["system:masters"] # A list of groups within Kubernetes to which the role is mapped; Checkout K8s Role and Rolebindings
    }
  ]

  # EKS MANAGED NODE GROUPS
  managed_node_groups = {
    mg_5 = {
      node_group_name = local.node_group_name
      instance_types  = ["m5.xlarge"]
      subnet_ids      = module.vpc.private_subnets
    }
  }

  tags = local.tags
}

#   ## EKS add-ons


module "kubernetes_addons" {
  #source         = "github.com/aws-ia/terraform-aws-eks-blueprints?ref=v4.27.0/modules/kubernetes-addons"
  source         = "github.com/aws-ia/terraform-aws-eks-blueprints?ref=v4.32.1/modules/kubernetes-addons"
  eks_cluster_id = module.eks_blueprints.eks_cluster_id

  ## EKS Addons
  enable_aws_load_balancer_controller = true
  aws_load_balancer_controller_helm_config = {
    name            = "aws-load-balancer-controller"
    chart           = "aws-load-balancer-controller"
    service_account = "aws-lb-sa"
    namespace       = "kube-system"
  }

  enable_amazon_eks_vpc_cni = true
  amazon_eks_vpc_cni_config = {
    addon_name      = "vpc-cni"
    addon_version   = local.eks_addon_vpc_cni_version
    service_account = "aws-node"
  }
  enable_amazon_eks_coredns = true
  amazon_eks_coredns_config = {
    addon_name      = "coredns"
    addon_version   = local.eks_addon_coredns_version
    service_account = "coredns"
  }
  enable_amazon_eks_kube_proxy = true
  amazon_eks_kube_proxy_config = {
    addon_name      = "kube-proxy"
    addon_version   = local.eks_addon_kube_proxy_version
    service_account = "kube-proxy"
  }
}
################################################################################
# Restrict traffic flow using Network Policies
################################################################################

# Block all ingress and egress traffic within the stars namespace
resource "kubernetes_network_policy_v1" "default_deny_stars" {
  metadata {
    name      = "default-deny"
    namespace = "stars"
  }
  spec {
    policy_types = ["Ingress"]
    pod_selector {
      match_labels = {}
    }
  }
  depends_on = [module.kubernetes_addons]
}

# Block all ingress and egress traffic within the client namespace
resource "kubernetes_network_policy_v1" "default_deny_client" {
  metadata {
    name      = "default-deny"
    namespace = "client"
  }
  spec {
    policy_types = ["Ingress"]
    pod_selector {
      match_labels = {}
    }
  }
  depends_on = [module.kubernetes_addons]
}

# Allow the management-ui to access the star application pods
resource "kubernetes_network_policy_v1" "allow_ui_to_stars" {
  metadata {
    name      = "allow-ui"
    namespace = "stars"
  }
  spec {
    policy_types = ["Ingress"]
    pod_selector {
      match_labels = {}
    }
    ingress {
      from {
        namespace_selector {
          match_labels = {
            role = "management-ui"
          }
        }
      }
    }
  }
  depends_on = [module.kubernetes_addons]
}

# Allow the management-ui to access the client application pods
resource "kubernetes_network_policy_v1" "allow_ui_to_client" {
  metadata {
    name      = "allow-ui"
    namespace = "client"
  }
  spec {
    policy_types = ["Ingress"]
    pod_selector {
      match_labels = {}
    }
    ingress {
      from {
        namespace_selector {
          match_labels = {
            role = "management-ui"
          }
        }
      }
    }
  }
  depends_on = [module.kubernetes_addons]
}

# Allow the frontend pod to access the backend pod within the stars namespace
resource "kubernetes_network_policy_v1" "allow_frontend_to_backend" {
  metadata {
    name      = "backend-policy"
    namespace = "stars"
  }
  spec {
    policy_types = ["Ingress"]
    pod_selector {
      match_labels = {
        role = "backend"
      }
    }
    ingress {
      from {
        pod_selector {
          match_labels = {
            role = "frontend"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "6379"
      }
    }
  }
  depends_on = [module.kubernetes_addons]
}

# Allow the client pod to access the frontend pod within the stars namespace
resource "kubernetes_network_policy_v1" "allow_client_to_backend" {
  metadata {
    name      = "frontend-policy"
    namespace = "stars"
  }

  spec {
    policy_types = ["Ingress"]
    pod_selector {
      match_labels = {
        role = "frontend"
      }
    }
    ingress {
      from {
        namespace_selector {
          match_labels = {
            role = "client"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "80"
      }
    }
  }
  depends_on = [module.kubernetes_addons]
}
