#!/bin/bash
if [ -d "./publish" ]; then
  echo "Remove existing publish directory...\n"
  rm -rf ./publish
fi

dotnet test SimpleMFA.Net.sln \
  --configuration UnitTest

dotnet build SimpleMFA.NET.sln \
  --configuration Release \
  --no-restore \
  --output ./publish