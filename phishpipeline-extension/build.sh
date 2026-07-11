#!/bin/bash
# Package extension for Chrome Web Store or distribution

echo "Building PhishPipeline extension..."

# Generate icons (python3 on Unix, python on Windows)
PY=$(command -v python3 || command -v python)
"$PY" create_icons.py

# Create dist package
mkdir -p dist
cp manifest.json dist/
cp popup.html dist/
cp popup.css dist/
cp popup.js dist/
cp background.js dist/
cp -r icons/ dist/

# Create ZIP for Chrome Web Store upload (zip if available, python fallback)
if command -v zip > /dev/null 2>&1; then
  zip -r phishpipeline-extension.zip dist/ -x "*.DS_Store"
else
  "$PY" -c "
import shutil
shutil.make_archive('phishpipeline-extension', 'zip', root_dir='.', base_dir='dist')
print('Created phishpipeline-extension.zip (python fallback)')
"
fi

echo "✓ Extension packaged: phishpipeline-extension.zip"
echo "✓ Load unpacked from: dist/"
echo ""
echo "To install in Chrome:"
echo "  chrome://extensions → Developer Mode → Load unpacked → select dist/"
