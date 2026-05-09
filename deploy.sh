#!/bin/bash
# Easy Deployment Script for Monster Spawned Studios Security Monitoring Stack

set -e

echo "🛡️  Monster Spawned Studios"
echo "🚀 Starting Advanced Network Security Monitoring Stack Deployment..."

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose v2+."
    exit 1
fi

# Create .env from example if it doesn't exist
if [ ! -f .env ]; then
    echo "📄 Creating .env from .env.example..."
    cp .env.example .env
    echo "⚠️  Please edit .env with your actual values before continuing!"
    echo "   Especially: Cloudflare token, Discord webhook, email, OpenWRT SSH, etc."
    read -p "Press Enter after you have edited .env..."
fi

# Create necessary directories
mkdir -p logs rules ssh-keys grafana-data prometheus-data evebox-data geoip-data

# Set proper permissions
chmod 600 .env 2>/dev/null || true
chmod 700 ssh-keys 2>/dev/null || true

echo "✅ Starting all services..."
docker compose up -d

echo ""
echo "🎉 Deployment complete!"
echo ""
echo "Access points:"
echo "  - EveBox Dashboard:   https://localhost:5636"
echo "  - Grafana:            http://localhost:3000   (admin / admin123)"
echo "  - Prometheus:         http://localhost:9090"
echo ""
echo "Next steps:"
echo "  1. Change Grafana admin password immediately"
echo "  2. Configure your Cloudflare Tunnel"
echo "  3. Set up OpenWRT SSH key if using banIP auto-blocking"
echo "  4. (Optional) Set ENABLE_GEOIP_MAP=true in .env for World Map"
echo ""
echo "To view logs: docker compose logs -f"
echo "To stop:      docker compose down"
