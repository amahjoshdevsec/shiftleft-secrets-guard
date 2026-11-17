output "gate_mode" {
  value = var.gate_mode
}

output "onboarded_repos" {
  value = var.onboarded_repos
}

output "managed_files" {
  description = "Files committed into each repo (repo mode)."
  value       = keys(local.repo_files)
}
