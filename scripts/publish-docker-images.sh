# Publishing a Docker image to AWS Public ECR
# https://docs.google.com/document/d/1MRV9UuyaPHdC6oz9ZzknQjFm03UpORojDGd_tjzwYDg/edit?usp=sharing
#

# Authenticate Docker to public ECR
aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws

aws ecr-public create-repository --repository-name sparsity-ai/odyn --region us-east-1
aws ecr-public create-repository --repository-name sparsity-ai/sleeve --region us-east-1

# Push each image
for REPO in odyn sleeve; do
  REPO_URI=$(aws ecr-public describe-repositories \
    --repository-names sparsity-ai/$REPO \
    --region us-east-1 \
    --query "repositories[0].repositoryUri" --output text)

  docker tag $REPO:latest $REPO_URI:latest
  docker push $REPO_URI:latest
done

# Done! Your image is now public
echo "Image pushed to: $REPO_URI:latest"
