locals {
  content = templatefile("${path.module}/contiguous.tf.template", {
    max_number_of_ranges = 100
  })
}

module "local-file-data" {
  source  = "Invicton-Labs/file-data/local"
  version = ">=0.2.0"

  filename       = "${path.module}/../contiguous.tf"
  max_characters = length(local.content)
  content        = local.content
}
