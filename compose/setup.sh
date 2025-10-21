#!/bin/bash
# Setup script for mcp-ssh-orchestrator docker-compose environment

set -e

echo "🚀 Setting up mcp-ssh-orchestrator docker-compose environment..."

# Create required directories
echo "📁 Creating directories..."
mkdir -p ../config ../keys ../secrets

# Copy example configuration files
echo "📋 Copying example configuration files..."
if [ -f "../examples/example-servers.yml" ]; then
    cp ../examples/example-servers.yml ../config/servers.yml
    echo "  ✓ servers.yml"
else
    echo "  ⚠️  example-servers.yml not found"
fi

if [ -f "../examples/example-credentials.yml" ]; then
    cp ../examples/example-credentials.yml ../config/credentials.yml
    echo "  ✓ credentials.yml"
else
    echo "  ⚠️  example-credentials.yml not found"
fi

if [ -f "../examples/example-policy.yml" ]; then
    cp ../examples/example-policy.yml ../config/policy.yml
    echo "  ✓ policy.yml"
else
    echo "  ⚠️  example-policy.yml not found"
fi

# Copy environment file
echo "🔧 Setting up environment..."
if [ -f ".env.example" ]; then
    cp .env.example .env
    echo "  ✓ .env created from .env.example"
else
    echo "  ⚠️  .env.example not found"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit ../config/servers.yml with your server details"
echo "2. Edit ../config/credentials.yml with your credentials"
echo "3. Edit ../config/policy.yml with your security policies"
echo "4. Add SSH keys to ../keys/ directory"
echo "5. Add any password files to ../secrets/ directory"
echo "6. Run: docker compose up --build"
echo ""
