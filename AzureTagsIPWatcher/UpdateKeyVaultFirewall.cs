using System;
using System.Collections.Generic; // 📌 Para List<>
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Azure;
using Azure.Data.Tables;
using Azure.Identity;
using Azure.Security.KeyVault.Administration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker; // 📌 Para [Function] y [HttpTrigger]
using Microsoft.Azure.Functions.Worker.Http; // 📌 Para HttpRequestData
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;


public class UpdateKeyVaultFirewall
{
    private readonly HttpClient _httpClient = new();
    private readonly ILogger<UpdateKeyVaultFirewall> _logger;

    public UpdateKeyVaultFirewall(ILogger<UpdateKeyVaultFirewall> logger)
    {
        _logger = logger;
    }

    [Function("UpdateKeyVaultFirewallFunction")]
    public async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        _logger.LogInformation("🔹 Iniciando la actualización del Firewall de Key Vault...");

        // 📌 Parámetros de configuración
        string storageAccount = Environment.GetEnvironmentVariable("AzureStorageAccount");
        string tableName = Environment.GetEnvironmentVariable("TableName");
        string keyVaultName = Environment.GetEnvironmentVariable("KeyVaultName");
        string subscriptionId = Environment.GetEnvironmentVariable("SubscriptionId");
        string resourceGroupName = Environment.GetEnvironmentVariable("ResourceGroupName");
        string clientId = Environment.GetEnvironmentVariable("ClientId");
        string clientSecret = Environment.GetEnvironmentVariable("ClientSecret");
        string tenantId = Environment.GetEnvironmentVariable("TenantId");

        try
        {
            // 🔹 1️⃣ Obtener la última IP registrada en la tabla de Azure Storage
            string latestIP = await GetLatestIP(storageAccount, tableName);
            _logger.LogInformation($"🔹 Última IP obtenida: {latestIP}");

            // 🔹 2️⃣ Obtener las IPs actuales en el Firewall de Key Vault
            var existingIPs = await GetKeyVaultFirewallIPs(subscriptionId, resourceGroupName, keyVaultName, clientId, clientSecret, tenantId);

            // 🔹 3️⃣ Comparar IPs y actualizar si es necesario
            if (!existingIPs.Contains(latestIP))
            {
                existingIPs.Add(latestIP);
                await UpdateKeyVaultFirewallRules(subscriptionId, resourceGroupName, keyVaultName, existingIPs, clientId, clientSecret, tenantId);
                _logger.LogInformation("✅ Firewall de Key Vault actualizado correctamente.");
            }
            else
            {
                _logger.LogInformation("ℹ️ No se detectaron cambios en las IPs.");
            }

            return new OkObjectResult("Proceso completado.");
        }
        catch (Exception ex)
        {
            _logger.LogError($"❌ Error en la actualización: {ex.Message}");
            return new BadRequestObjectResult($"Error: {ex.Message}");
        }
    }

    // 🔹 Método para obtener la última IP desde Azure Table Storage
    private async Task<string> GetLatestIP(string storageAccount, string tableName)
    {
        var serviceClient = new TableServiceClient(new Uri($"https://{storageAccount}.table.core.windows.net"), new DefaultAzureCredential());
        var tableClient = serviceClient.GetTableClient(tableName);

        var entities = tableClient.QueryAsync<TableEntity>($"PartitionKey eq 'FirewallUpdate'", 1);
        await foreach (var entity in entities)
        {
            return entity["IP"].ToString();
        }

        throw new Exception("No se encontraron registros en la tabla.");
    }

    // 🔹 Método para obtener las IPs actuales en el Firewall del Key Vault
    private async Task<List<string>> GetKeyVaultFirewallIPs(string subscriptionId, string resourceGroup, string keyVaultName, string clientId, string clientSecret, string tenantId)
    {
        string token = await GetAzureAccessToken(clientId, clientSecret, tenantId);
        string uri = $"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.KeyVault/vaults/{keyVaultName}/firewallRules?api-version=2022-07-01";

        HttpRequestMessage request = new(HttpMethod.Get, uri);
        request.Headers.Add("Authorization", $"Bearer {token}");

        HttpResponseMessage response = await _httpClient.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            throw new Exception($"Error obteniendo reglas del firewall: {response.ReasonPhrase}");
        }

        var result = await response.Content.ReadAsStringAsync();
        dynamic json = JsonConvert.DeserializeObject(result);

        return json.value.ToObject<List<string>>();
    }

    // 🔹 Método para actualizar las reglas del Firewall en el Key Vault
    private async Task UpdateKeyVaultFirewallRules(string subscriptionId, string resourceGroup, string keyVaultName, List<string> updatedIPs, string clientId, string clientSecret, string tenantId)
    {
        string token = await GetAzureAccessToken(clientId, clientSecret, tenantId);
        string uri = $"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.KeyVault/vaults/{keyVaultName}/firewallRules/default?api-version=2022-07-01";

        var body = new
        {
            properties = new
            {
                ipRules = updatedIPs.Select(ip => new { value = ip }).ToArray()
            }
        };

        HttpRequestMessage request = new(HttpMethod.Put, uri)
        {
            Content = new StringContent(JsonConvert.SerializeObject(body), Encoding.UTF8, "application/json")
        };
        request.Headers.Add("Authorization", $"Bearer {token}");

        HttpResponseMessage response = await _httpClient.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            throw new Exception($"Error actualizando reglas del firewall: {response.ReasonPhrase}");
        }
    }

    // 🔹 Método para obtener un Token de acceso de Azure
    private async Task<string> GetAzureAccessToken(string clientId, string clientSecret, string tenantId)
    {
        var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
        var token = await credential.GetTokenAsync(new Azure.Core.TokenRequestContext(new[] { "https://management.azure.com/.default" }));
        return token.Token;
    }
}
