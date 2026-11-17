# Layer 4: onboarding as code. One PR that adds a repo to `onboarded_repos` onboards it to the
# security gate. No ClickOps, full audit trail in git.
#
# gate_mode = "repo" (any paid plan): Terraform commits the gate workflow and the engine into each
#   repo, then adds a ruleset that requires the `secret-guard` check before merging.
# gate_mode = "org" (GitHub Enterprise Cloud): one organization ruleset runs the workflow from
#   this central repo as a required workflow. Nothing is copied into the target repos.

terraform {
  required_version = ">= 1.5"
  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.13"
    }
  }
}

provider "github" {
  owner = var.github_org
  # Auth via GITHUB_TOKEN or, in CI, a GitHub App (app_auth block). Never hardcode it here.
}

locals {
  bypass_actors = concat(
    # Break-glass: AppSec can bypass through a pull request; GitHub logs every bypass.
    var.appsec_team_id == null ? [] : [{ id = var.appsec_team_id, type = "Team", mode = "pull_request" }],
    # The GitHub App that runs this Terraform, so it can update the files it manages.
    var.terraform_app_id == null ? [] : [{ id = var.terraform_app_id, type = "Integration", mode = "always" }],
  )

  managed_files = {
    ".github/workflows/secret-guard.yml"   = "${path.module}/../.github/workflows/secret-guard.yml"
    ".github/secret-guard/secret_guard.py" = "${path.module}/../guard/secret_guard.py"
  }

  repo_files = var.gate_mode != "repo" ? {} : {
    for pair in setproduct(var.onboarded_repos, keys(local.managed_files)) :
    "${pair[0]}:${pair[1]}" => { repo = pair[0], path = pair[1], source = local.managed_files[pair[1]] }
  }

  sensitive_paths = [".env", "**/.env", "**/*.pem", "**/*.key", "**/*.tfstate", "**/id_rsa", "**/id_ed25519"]
}

# --------------------------------------------------------------------------- repo mode

# The required check must exist before it is required, or every PR in the repo waits forever
# for a status that never reports. So the workflow goes in first.
resource "github_repository_file" "gate" {
  for_each            = local.repo_files
  repository          = each.value.repo
  file                = each.value.path
  content             = file(each.value.source)
  commit_message      = "chore(security): onboard to secret-guard (managed by Terraform)"
  overwrite_on_create = false # never clobber a file a team already has; resolve by hand
}

resource "github_repository_ruleset" "security_gate" {
  for_each    = var.gate_mode == "repo" ? toset(var.onboarded_repos) : toset([])
  name        = "security-gate"
  repository  = each.value
  target      = "branch"
  enforcement = var.enforcement

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }

  dynamic "bypass_actors" {
    for_each = local.bypass_actors
    content {
      actor_id    = bypass_actors.value.id
      actor_type  = bypass_actors.value.type
      bypass_mode = bypass_actors.value.mode
    }
  }

  rules {
    pull_request {
      required_approving_review_count = 1
      require_code_owner_review       = true # CODEOWNERS routes guard/config changes to AppSec
    }
    required_status_checks {
      strict_required_status_checks_policy = false
      required_check {
        context = "secret-guard"
      }
    }
  }

  depends_on = [github_repository_file.gate]
}

# --------------------------------------------------------------------------- org mode

data "github_repository" "central" {
  count = var.gate_mode == "org" ? 1 : 0
  name  = var.workflow_repo
}

resource "github_organization_ruleset" "security_gate" {
  count       = var.gate_mode == "org" ? 1 : 0
  name        = "security-gate"
  target      = "branch"
  enforcement = var.enforcement

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
    repository_name {
      include = var.onboarded_repos # ["~ALL"] once the org is baselined
      exclude = []
    }
  }

  dynamic "bypass_actors" {
    for_each = local.bypass_actors
    content {
      actor_id    = bypass_actors.value.id
      actor_type  = bypass_actors.value.type
      bypass_mode = bypass_actors.value.mode
    }
  }

  rules {
    pull_request {
      required_approving_review_count = 1
      require_code_owner_review       = true
    }
    required_workflows {
      required_workflow {
        repository_id = data.github_repository.central[0].repo_id
        path          = ".github/workflows/secret-guard.yml"
        ref           = var.workflow_ref
      }
    }
  }
}

# Push ruleset: GitHub rejects the push itself if it adds a credential file. Enterprise Cloud.
resource "github_organization_ruleset" "block_sensitive_files" {
  count       = var.block_sensitive_files_on_push ? 1 : 0
  name        = "block-credential-files"
  target      = "push"
  enforcement = var.enforcement

  conditions {
    repository_name {
      include = var.onboarded_repos
      exclude = []
    }
  }

  dynamic "bypass_actors" {
    for_each = local.bypass_actors
    content {
      actor_id    = bypass_actors.value.id
      actor_type  = bypass_actors.value.type
      bypass_mode = bypass_actors.value.mode
    }
  }

  rules {
    file_path_restriction {
      restricted_file_paths = local.sensitive_paths
    }
  }
}

# --------------------------------------------------------------------------- org defaults (opt-in)

# WARNING: github_organization_settings manages the WHOLE organization profile. Attributes not
# set here (members_can_create_repositories, default_repository_permission, ...) fall back to
# provider defaults and can silently change org policy. Only enable after `terraform import`
# and a reviewed plan. It also only affects NEW repositories; existing ones are covered by the
# gate above (and by GitHub code security configurations, managed outside this module).
resource "github_organization_settings" "security_defaults" {
  count         = var.manage_org_defaults ? 1 : 0
  billing_email = var.billing_email

  advanced_security_enabled_for_new_repositories               = true
  secret_scanning_enabled_for_new_repositories                 = true
  secret_scanning_push_protection_enabled_for_new_repositories = true
  dependabot_alerts_enabled_for_new_repositories               = true
  dependency_graph_enabled_for_new_repositories                = true

  lifecycle {
    precondition {
      condition     = var.billing_email != null
      error_message = "billing_email is required when manage_org_defaults = true."
    }
  }
}
