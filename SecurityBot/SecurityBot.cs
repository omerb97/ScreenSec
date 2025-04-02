using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Azure.Storage.Blobs;
using Microsoft.Bot.Builder;
using Microsoft.Bot.Schema;
using SecurityScreenshotBot.Models;

namespace SecurityScreenshotBot.Bots
{
    public class SecurityBot : ActivityHandler
    {
        // Read from configuration (Environment Variables or appsettings.json)
        private readonly string _blobConnectionString = "<YourBlobConnectionString>";
        private readonly string _blobContainerName = "screenshots";
        private readonly BlobContainerClient _containerClient;

        public SecurityBot()
        {
            // Create a BlobContainerClient for uploading images.
            var blobServiceClient = new BlobServiceClient(_blobConnectionString);
            _containerClient = blobServiceClient.GetBlobContainerClient(_blobContainerName);
            _containerClient.CreateIfNotExists();
        }

        protected override async Task OnMessageActivityAsync(ITurnContext<IMessageActivity> turnContext, CancellationToken cancellationToken)
        {
            // Check if the activity has any attachments
            if (turnContext.Activity.Attachments != null && turnContext.Activity.Attachments.Count > 0)
            {
                // Assume the first attachment is the image
                var attachment = turnContext.Activity.Attachments[0];

                // Download the image from the attachment URL
                var imageData = await DownloadImageAsync(attachment.ContentUrl);

                // Generate a unique file name (GUID)
                var fileName = $"{Guid.NewGuid()}.png";

                // Upload the image to Blob Storage
                var blobUrl = await UploadToBlobAsync(fileName, imageData);

                // Inform the user that the image has been uploaded
                await turnContext.SendActivityAsync(MessageFactory.Text($"Image received and uploaded. \nProcessing..."), cancellationToken);

                // OPTIONAL: You might store the mapping of conversation/user to file name for later retrieval of the report.
                // Optionally, wait a few seconds (or use a retry mechanism) to allow the function to complete.
                int maxRetries = 5;
                int retryTime = 5000;
                await Task.Delay(retryTime);
                for (int i = 0; i < maxRetries; i++)
                {
                    // Check if the report is ready (this could be a call to another service or a database check)
                    BotResponse report = await GetReportAsync(fileName); // Use the same file name without extension adjustments if needed.
                    if (report != null && !string.IsNullOrEmpty(report.SecurityAnalysis))
                    {
                        // Send the report back to the user
                        await turnContext.SendActivityAsync(MessageFactory.Text($"{report.SecurityAnalysis}"));
                        return;
                    }
                    await Task.Delay(retryTime);
                }
                await turnContext.SendActivityAsync(MessageFactory.Text($"A problem occured. Try again"));
            }
            else
            {
                await turnContext.SendActivityAsync(MessageFactory.Text("Please attach a screenshot image for analysis."), cancellationToken);
            }
        }

        private async Task<byte[]> DownloadImageAsync(string imageUrl)
        {
            using var httpClient = new HttpClient();
            return await httpClient.GetByteArrayAsync(imageUrl);
        }

        private async Task<string> UploadToBlobAsync(string fileName, byte[] data)
        {
            // Get a reference to a blob
            var blobClient = _containerClient.GetBlobClient(fileName);

            using (var stream = new MemoryStream(data))
            {
                await blobClient.UploadAsync(stream, overwrite: true);
            }

            // In production, you might want to return a SAS URL. For now, we return the blob URL.
            return blobClient.Uri.ToString();
        }
        public async Task<BotResponse> GetReportAsync(string fileName)
        {
            // Create a BlobServiceClient using your blob connection string.
            var blobServiceClient = new BlobServiceClient(_blobConnectionString);
            // Get a reference to the "reports" container.
            var containerClient = blobServiceClient.GetBlobContainerClient("reports");
            // Assume the report file has the same name as the image but with a .json extension.
            var reportBlobClient = containerClient.GetBlobClient($"{fileName}.json");

            if (await reportBlobClient.ExistsAsync())
            {
                // Download the blob content.
                var downloadResponse = await reportBlobClient.DownloadContentAsync();
                // Get the JSON string from the downloaded content
                var jsonString = downloadResponse.Value.Content.ToString();
                // Deserialize the JSON string into a BotResponse object
                var options = new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };
                var botResponse = System.Text.Json.JsonSerializer.Deserialize<BotResponse>(jsonString, options);
                // Return the security analysis from the bot response
                if (botResponse != null && !string.IsNullOrEmpty(botResponse.SecurityAnalysis)){
                    return botResponse;
                } else{
                    return null;
                }
            }
            else
            {
                return null;
            }
        }
    }
}