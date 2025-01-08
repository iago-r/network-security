#!/bin/bash
set -eu

# Check if only 1 argument was passed
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <source_directory>"
    exit 1
fi

# Argument for the directory to be copied
SOURCE=$1

DEST_DIR="input_config" 
# volume in compose 
DESTINATION="/shared_data/$DEST_DIR"

# Check if the source directory exists
if [ ! -d "$SOURCE" ]; then
    echo "Error: Source directory '$SOURCE' does not exist."
    exit 1
fi

# Check if the destination directory exists, if not, create it
docker compose exec framework bash -c "mkdir -p $DESTINATION && rm -rf $DESTINATION/*"

# command that deletes all configuration files if any before copying the new ones.

# Copy only the .json content from the source directory to the volume
for file in "$SOURCE"/*.json; do
    if [ -f "$file" ]; then
        docker compose cp "$file" framework:"$DESTINATION/$(basename "$file")"
    fi
done

echo "Content copied from $SOURCE to $DESTINATION successfully."
