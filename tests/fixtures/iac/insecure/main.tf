resource "aws_s3_bucket" "public" {
  bucket        = "public-aegis-bucket"
  acl           = "public-read"
  force_destroy = true
}
