# Azure App Service Deployment Script for The Moses Method Structures, LLC
# Prerequisites: Azure CLI installed (`winget install Microsoft.AzureCLI`) and `az login` executed.

$RESOURCE_GROUP = "rg-moses-audit-prod"
$LOCATION = "westus2"
$ACR_NAME = "acrmosesaudit" + (Get-Random -Minimum 1000 -Maximum 9999)
$APP_SERVICE_PLAN = "asp-moses-audit"
$WEB_APP_NAME = "moses-audit-engine-" + (Get-Random -Minimum 1000 -Maximum 9999)

Write-Host "1. Creating Azure Resource Group ($RESOURCE_GROUP)..." -ForegroundColor Cyan
az group create --name $RESOURCE_GROUP --location $LOCATION

Write-Host "2. Creating Azure Container Registry ($ACR_NAME)..." -ForegroundColor Cyan
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic --admin-enabled true

Write-Host "3. Building Docker Image directly in ACR..." -ForegroundColor Cyan
az acr build --registry $ACR_NAME --image moses-audit-engine:v1 .

Write-Host "4. Creating App Service Plan ($APP_SERVICE_PLAN)..." -ForegroundColor Cyan
az appservice plan create --name $APP_SERVICE_PLAN --resource-group $RESOURCE_GROUP --sku B1 --is-linux

Write-Host "5. Deploying Containerized Web App ($WEB_APP_NAME)..." -ForegroundColor Cyan
az webapp create --resource-group $RESOURCE_GROUP --plan $APP_SERVICE_PLAN --name $WEB_APP_NAME --deployment-container-image-name "$ACR_NAME.azurecr.io/moses-audit-engine:v1"

Write-Host "6. Configuring Environment Variables..." -ForegroundColor Cyan
az webapp config appsettings set --resource-group $RESOURCE_GROUP --name $WEB_APP_NAME --settings SECRET_KEY="MOSES_METHOD_SECRET_KEY_2026"

Write-Host "`nDeployment Script Completed!" -ForegroundColor Green
Write-Host "App URL: https://$WEB_APP_NAME.azurewebsites.net" -ForegroundColor Yellow
