variable "github_org" {
  type        = string
  description = "GitHub organization to manage."
}

variable "onboarded_repos" {
  type        = list(string)
  description = "Repos onboarded to the security gate. Add a repo here in a PR to onboard it."
  default     = []
}

variable "gate_mode" {
  type        = string
  description = "repo: copy the workflow into each repo and require its check. org: org ruleset with a required workflow (Enterprise Cloud)."
  default     = "repo"
  validation {
    condition     = contains(["repo", "org"], var.gate_mode)
    error_message = "gate_mode must be repo or org."
  }
}

variable "enforcement" {
  type        = string
  description = "evaluate (report-only, Enterprise) during rollout, active once baselined."
  default     = "active"
  validation {
    condition     = contains(["evaluate", "active", "disabled"], var.enforcement)
    error_message = "enforcement must be evaluate, active, or disabled."
  }
}

variable "appsec_team_id" {
  type        = number
  description = "Team id allowed to bypass the gate through a PR (break-glass). Null disables it."
  default     = null
}

variable "terraform_app_id" {
  type        = number
  description = "GitHub App id that runs this Terraform, so it can update managed files despite the ruleset."
  default     = null
}

variable "workflow_repo" {
  type        = string
  description = "org mode: the central repo that holds .github/workflows/secret-guard.yml."
  default     = "shiftleft-secrets-guard"
}

variable "workflow_ref" {
  type        = string
  description = "org mode: ref of the required workflow. Pin to a tag or SHA in production."
  default     = "refs/heads/main"
}

variable "block_sensitive_files_on_push" {
  type        = bool
  description = "Org push ruleset that rejects pushes adding .env, *.pem, *.tfstate, etc. (Enterprise Cloud)."
  default     = false
}

variable "manage_org_defaults" {
  type        = bool
  description = "Manage github_organization_settings. Read the warning in main.tf first."
  default     = false
}

variable "billing_email" {
  type        = string
  description = "Required by github_organization_settings when manage_org_defaults = true."
  default     = null
}
