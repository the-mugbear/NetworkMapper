#!/bin/bash

# Quick verification script to check .gnmap support in code

echo "🔍 VERIFYING .GNMAP SUPPORT IN SOURCE CODE"
echo "=========================================="

echo ""
echo "📁 Frontend Upload.tsx:"
if grep -n "gnmap" frontend/src/pages/Upload.tsx; then
    echo "✅ Found .gnmap references in Upload.tsx"
else
    echo "❌ NO .gnmap references in Upload.tsx"
fi

echo ""
echo "🔧 Backend Parser:"
if ls backend/app/parsers/gnmap_parser.py >/dev/null 2>&1; then
    echo "✅ GnmapParser exists"
    echo "   Lines: $(wc -l < backend/app/parsers/gnmap_parser.py)"
else
    echo "❌ GnmapParser missing"
fi

echo ""
echo "🔌 Backend Upload Endpoint:"
if grep -n "gnmap" backend/app/api/v1/endpoints/upload.py; then
    echo "✅ Found .gnmap support in upload endpoint"
else
    echo "❌ NO .gnmap support in upload endpoint"
fi

echo ""
echo "📋 Package.json version:"
grep '"version"' frontend/package.json

echo ""
echo "🐍 Backend version:"
grep 'version=' backend/app/main.py

echo ""
echo "📦 Docker files cache-busting:"
if grep -n "CACHE_BUST" frontend/Dockerfile backend/Dockerfile; then
    echo "✅ Cache-busting arguments present"
else
    echo "❌ Cache-busting missing"
fi

echo ""
echo "🧪 Testing sample file:"
if [ -f "sample_gnmap.gnmap" ]; then
    echo "✅ Sample .gnmap file exists ($(wc -l < sample_gnmap.gnmap) lines)"
else
    echo "❌ Sample .gnmap file missing"
fi

echo ""
echo "=========================================="
echo "✅ Code verification complete"