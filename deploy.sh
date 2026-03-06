#!/bin/bash

echo "Starting deployment..."

cd ~/Motera_Server || exit

git pull origin main

npm install

pm2 reload all

echo "Deployment completed!"
