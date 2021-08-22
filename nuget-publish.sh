#!/bin/bash
usage()
{
  echo "Usage: ./nuget-publish.sh -k API_KEY"
  exit 2
}

while getopts 'k:v:' c; do
  case $c in
    k) API_KEY=$OPTARG ;;
    v) VERSION=$OPTARG ;;
    ?) usage ;;
  esac
done

if [ -z $API_KEY ]; then
  usage
fi

if [ -z $VERSION ]; then
  VERSION=1.0.0
fi

echo '.NET build package start...'
if [ -d './nupkgs' ]; then
  echo 'Removing previous package result'
  rm -rf ./nupkgs
fi
dotnet pack ./SimpleMFA.Net.Core/SimpleMFA.Net.Core.csproj \
  -p:PackageVersion=$VERSION \
  --output nupkgs || exit 1

echo '.NET publish package...'
dotnet nuget push ./nupkgs/SimpleMFA.Net.$VERSION.nupkg \
	--api-key $API_KEY \
  -s https://api.nuget.org/v3/index.json

echo 'Package publish successfully'
