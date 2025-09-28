#!/bin/bash

# Docker build script for GitHub webhook fanout server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
IMAGE_NAME="github-webhook-fanout"
TAG="latest"
BUILD_TYPE="dev"

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --tag TAG        Set image tag (default: latest)"
    echo "  -n, --name NAME      Set image name (default: github-webhook-fanout)"
    echo "  -p, --prod          Use production Dockerfile"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Build dev image with latest tag"
    echo "  $0 -t v1.0.0                 # Build dev image with v1.0.0 tag"
    echo "  $0 -p -t v1.0.0             # Build production image with v1.0.0 tag"
    echo "  $0 -n my-webhook -t dev      # Build with custom name and tag"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -p|--prod)
            BUILD_TYPE="prod"
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Set Dockerfile based on build type
if [ "$BUILD_TYPE" = "prod" ]; then
    DOCKERFILE="Dockerfile.prod"
    echo -e "${BLUE}Building production image...${NC}"
else
    DOCKERFILE="Dockerfile"
    echo -e "${BLUE}Building development image...${NC}"
fi

# Build the Docker image
echo -e "${YELLOW}Building Docker image: ${IMAGE_NAME}:${TAG}${NC}"
echo -e "${YELLOW}Using Dockerfile: ${DOCKERFILE}${NC}"

if docker build -f "$DOCKERFILE" -t "${IMAGE_NAME}:${TAG}" .; then
    echo -e "${GREEN}✅ Docker image built successfully!${NC}"
    echo -e "${GREEN}Image: ${IMAGE_NAME}:${TAG}${NC}"
    
    # Show image size
    echo -e "${BLUE}Image size:${NC}"
    docker images "${IMAGE_NAME}:${TAG}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
    
    # Show available commands
    echo ""
    echo -e "${YELLOW}Available commands:${NC}"
    echo -e "  Run container:     ${BLUE}docker run -p 8080:8080 ${IMAGE_NAME}:${TAG}${NC}"
    echo -e "  Run with env:      ${BLUE}docker run -p 8080:8080 --env-file .env ${IMAGE_NAME}:${TAG}${NC}"
    echo -e "  Use docker-compose: ${BLUE}docker-compose up${NC}"
    
else
    echo -e "${RED}❌ Docker build failed!${NC}"
    exit 1
fi
