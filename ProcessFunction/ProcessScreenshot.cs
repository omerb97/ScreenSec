using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace SecurityScreenshotFunction
{
    public class ProcessScreenshot
    {
        private readonly HttpClient _httpClient;

        public ProcessScreenshot(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        // The BlobOutput attribute is applied to the method so that the return value is written to the blob.
        [Function("ProcessScreenshot")]
        [BlobOutput("reports/{name}.json", Connection = "AZURE_BLOB_CONNECTION_STRING")]
        public async Task<string> Run(
            [BlobTrigger("screenshots/{name}", Connection = "AZURE_BLOB_CONNECTION_STRING")] ReadOnlyMemory<byte> imageData,
            string name,
            FunctionContext context)
        {
            var logger = context.GetLogger("ProcessScreenshot");
            logger.LogInformation($"Processing blob: {name}, Size: {imageData.Length} bytes");

            // For processing, convert the ReadOnlyMemory<byte> to a byte array
            byte[] imageBytes = imageData.ToArray();

            // (Optional) Save the blob as a file for further processing
            string tempImagePath = Path.Combine(Path.GetTempPath(), name);
            await File.WriteAllBytesAsync(tempImagePath, imageBytes);

            bool isGemini = true; // Set this based on your logic or configuration

            // Now run your processing methods
            string ocrText = await ExtractTextFromImageAsync(tempImagePath, logger);
            string securityAnalysis = await AnalyzeSecurityVulnerabilitiesAsync(ocrText, logger, isGemini);
            //var contentModeration = await RunContentModerationAsync(ocrText, logger);

            var report = new
            {
                blobName = name,
                ocrText,
                securityAnalysis,
                //contentModeration
            };

            return JsonConvert.SerializeObject(report, Formatting.Indented);
        }

        private async Task<string> ExtractTextFromImageAsync(string imagePath, ILogger logger)
        {
            try
            {
                // 1. Set up Azure Computer Vision credentials
                var subscriptionKey = Environment.GetEnvironmentVariable("AZURE_VISION_KEY");
                var endpoint = Environment.GetEnvironmentVariable("AZURE_VISION_ENDPOINT")?.TrimEnd('/');
                
                if (string.IsNullOrEmpty(subscriptionKey) || string.IsNullOrEmpty(endpoint))
                {
                    logger.LogError("Missing Azure Vision credentials. Please check AZURE_VISION_KEY and AZURE_VISION_ENDPOINT environment variables.");
                    return "Error: Missing Azure Vision credentials";
                }
                
                logger.LogInformation($"Using Vision endpoint: {endpoint}");
                
                // 2. Set up the Read API URL - using the correct API version
                var ocrUrl = $"{endpoint}/vision/v3.2/read/analyze";
                logger.LogInformation($"OCR URL: {ocrUrl}");

                // 3. Prepare the image data
                byte[] imageData;
                try {
                    imageData = await File.ReadAllBytesAsync(imagePath);
                    logger.LogInformation($"Successfully read image file: {imagePath}, Size: {imageData.Length} bytes");
                }
                catch (Exception fileEx) {
                    logger.LogError($"Failed to read image file: {fileEx.Message}");
                    return $"Error: Failed to read image file - {fileEx.Message}";
                }
                
                // 4. Submit the image to the Vision API
                using var content = new ByteArrayContent(imageData);
                // Clear any existing headers to avoid conflicts
                content.Headers.Clear();
                content.Headers.Add("Ocp-Apim-Subscription-Key", subscriptionKey);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

                HttpResponseMessage response;
                try {
                    response = await _httpClient.PostAsync(ocrUrl, content);
                    logger.LogInformation($"Initial API response status: {response.StatusCode}");
                }
                catch (Exception httpEx) {
                    logger.LogError($"HTTP request failed: {httpEx.Message}");
                    return $"Error: HTTP request failed - {httpEx.Message}";
                }
                
                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    logger.LogError($"Vision API error: {response.StatusCode}, Content: {errorContent}");
                    
                    if (response.StatusCode == System.Net.HttpStatusCode.Forbidden) // 403
                    {
                        logger.LogError("Authentication error (403 Forbidden). Please check your subscription key and region/endpoint.");
                        return "Error: Authentication failed (403 Forbidden). Please verify your Azure Vision API key and endpoint.";
                    }
                    
                    return $"Error: {response.StatusCode} - {errorContent}";
                }
                
                // 5. Get the operation URL from the response headers
                if (!response.Headers.TryGetValues("Operation-Location", out var operationLocationValues))
                {
                    logger.LogError("No Operation-Location header found in Vision API response");
                    return "Error: No Operation-Location header found. The API response format may have changed.";
                }
                
                string operationLocation = operationLocationValues.FirstOrDefault();
                logger.LogInformation($"Got operation URL: {operationLocation}");
                
                // 6. Poll the operation URL until the operation completes
                int maxRetries = 10;
                int delay = 1000; // 1 second initial delay
                
                for (int i = 0; i < maxRetries; i++)
                {
                    logger.LogInformation($"Polling attempt {i+1}/{maxRetries}");
                    await Task.Delay(delay);
                    
                    // Create a new request to check the operation status
                    using var getRequest = new HttpRequestMessage(HttpMethod.Get, operationLocation);
                    getRequest.Headers.Add("Ocp-Apim-Subscription-Key", subscriptionKey);
                    
                    HttpResponseMessage getResponse;
                    try {
                        getResponse = await _httpClient.SendAsync(getRequest);
                    }
                    catch (Exception pollEx) {
                        logger.LogError($"Error during polling: {pollEx.Message}");
                        continue; // Try again
                    }
                    
                    string responseJson = await getResponse.Content.ReadAsStringAsync();
                    
                    if (!getResponse.IsSuccessStatusCode)
                    {
                        logger.LogError($"Error checking operation status: {getResponse.StatusCode}, Content: {responseJson}");
                        
                        if (i == maxRetries - 1) // Only return error on last retry
                        {
                            return $"Error: {getResponse.StatusCode} - {responseJson}";
                        }
                        
                        // Otherwise try again
                        continue;
                    }
                    
                    try
                    {
                        // Parse the response JSON
                        dynamic result = JsonConvert.DeserializeObject(responseJson);
                        
                        if (result == null)
                        {
                            logger.LogError("Failed to parse JSON response");
                            continue; // Try again
                        }
                        
                        string status = result.status?.ToString();
                        logger.LogInformation($"Operation status: {status}");
                        
                        if (string.IsNullOrEmpty(status))
                        {
                            logger.LogError("Status field missing from response");
                            continue; // Try again
                        }
                        
                        if (status == "succeeded")
                        {
                            // 7. Extract text from the analysis results
                            StringBuilder extractedText = new StringBuilder();
                            
                            try
                            {
                                // Extract from readResults
                                if (result.analyzeResult != null && result.analyzeResult.readResults != null)
                                {
                                    foreach (var readResult in result.analyzeResult.readResults)
                                    {
                                        if (readResult != null && readResult.lines != null)
                                        {
                                            foreach (var line in readResult.lines)
                                            {
                                                if (line != null && line.text != null)
                                                {
                                                    string lineText = line.text.ToString();
                                                    extractedText.AppendLine(lineText);
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                string text = extractedText.ToString().Trim();
                                
                                if (string.IsNullOrWhiteSpace(text))
                                {
                                    logger.LogWarning("No text was extracted from the image");
                                    return "No text found in image";
                                }
                                
                                logger.LogInformation($"Successfully extracted text: {text}");
                                return text;
                            }
                            catch (Exception extractEx)
                            {
                                logger.LogError($"Error extracting text from response: {extractEx.Message}");
                                logger.LogError($"Response structure: {responseJson}");
                                return $"Error extracting text: {extractEx.Message}";
                            }
                        }
                        else if (status == "failed")
                        {
                            var errorDetails = result.recognitionError?.ToString() ?? "Unknown error";
                            logger.LogError($"OCR operation failed: {errorDetails}");
                            return $"Error: OCR operation failed - {errorDetails}";
                        }
                        else if (status == "running" || status == "notStarted")
                        {
                            // Operation still in progress, continue polling
                            logger.LogInformation($"Operation still in progress: {status}");
                        }
                        else
                        {
                            logger.LogWarning($"Unexpected operation status: {status}");
                        }
                    }
                    catch (Exception jsonEx)
                    {
                        logger.LogError($"Error parsing JSON response: {jsonEx.Message}");
                        logger.LogError($"Response JSON: {responseJson}");
                        // Continue to next attempt rather than failing immediately
                    }
                    
                    // Increase delay with exponential backoff
                    delay = Math.Min(delay * 2, 10000); // Cap at 10 seconds
                }
                
                logger.LogError("Timed out waiting for OCR operation to complete");
                return "Error: OCR operation timed out after maximum retries";
            }
            catch (Exception ex)
            {
                logger.LogError($"Exception in ExtractTextFromImageAsync: {ex.Message}\n{ex.StackTrace}");
                return $"Error: {ex.Message}";
            }
        }

        private async Task<string> AnalyzeSecurityVulnerabilitiesAsync(string text, ILogger logger, bool isGemini)
        {
            string analysis;
            var oldPrompt = $"Analyze the following text for security vulnerabilities. Identify any exposed credentials, API keys, passwords, configuration settings, or other sensitive information. Provide a summary of findings with recommendations.\n\nText: {text}";
            var prompt = $@"You are a tech company's security officer. Your job is to scan images sent between workers to 
                            see if they might contain text that could lead to sensetive information to leak, or to lead to a 
                            security breach by hackers. The image has already been scanned and you are provided with a text inside the image.
                            Information like any exposed credentials, API keys, passwords, configuration settings, or other sensitive information.
                            Your out put show be in this format:
                            *Title*mage Security Scan Results*Title*
                            Line break

                            **Text found**
                            Line break
                            {text}
                            Line break
                            
                            **Determination**
                            Line break
                            Determination of whether there is a possilbe break in words: Yes, No, Maybe.
                            Format the determination in the following way:
                            If Yes: '**Security breach found!**'
                            If Maybe: 'Possible security breach'
                            If No: 'No security breach found'
                            If the determination was determined 'No' the report should end here and it should just stay 'You may send this image safely'

                            **Analysis**
                            *List by number the concerns. For each point the  it should begin with a bold 2-3 word summary, and then a detailed 2-3 sentences.*
                            Line break
                            **Recommended remediation or mitigation**
                            *Recommended remidiation or mitigation. Your recomndation should not be scolding. 
                            You are making a recomandation to the sender of the image. You shoud tell him what parts of the picture 
                            would need to be removed in order to be compliant. Keep in mind the sender is a programmer or product manager. He can crop parts of the 
                            picture in order to be compliant. He cannot use photoshop. List by number the recommendations. For each point the  it should begin with a bold 2-3 word summary, and then a detailed 2-3 sentences*
                           
                            Here are some examples of answers:
                            input: PASSWORDS qwerty123 abc 12345 654321abc 42Hvihu65!# 
                            output:*Image Security Scan Results* **Text found** PASSWORDS qwerty123 abc 12345 654321abc 42Hvihu65!# **Determination** **Security breach found!** **Analysis** 1.
                            **Exposed Passwords:** The image contains a list of what appear to be plaintext passwords. This poses a significant security risk as these passwords could be used to compromise user accounts or systems if they are in use.
                            2. **Weak Credentials:** The passwords listed (qwerty123, abc 12345, 654321abc) are very weak and easily guessable. This makes them highly susceptible to brute-force attacks or dictionary attacks, further increasing the risk of unauthorized access.
                            3. **Potential Scope:** Without additional context, it's impossible to determine the scope of the potential breach. The passwords might belong to low-level accounts, or they could be for critical systems or administrator accounts. 
                            **Recommended remediation or mitigation** 1. **Redact Sensitive Information:** Please crop or redact the section of the image containing the listed passwords before sharing it further. This is crucial to prevent accidental exposure of sensitive credentials.
                            2. **Password Rotation Encouraged:** If these passwords are in use, it's highly recommended that they be changed immediately. Consider encouraging the team to use a password manager and enforce strong password policies.
                            3. **Context Awareness:** Double-check all images for any potentially sensitive information, such as API keys, database connection strings, or internal configuration details, before sharing them. This will help prevent future security incidents. ""

                            input:X CONCO CBR 7C M PL STACJA DEMONTA?U POJAZDÓW GORCZENICA 91A TEL. 606470287
                            output: text:""Security Report: *Image Security Scan Results* **Text found** X CONCO CBR 7C M PL STACJA DEMONTA?U POJAZDÓW GORCZENICA 91A TEL. 606470287 **Determination** No security breach found You may send this image safely 


                            Text{text}";

            if (isGemini)
            {
                var geminiKey = Environment.GetEnvironmentVariable("GOOGLE_GEMINI_KEY");
                logger.LogInformation("Using Gemini for security analysis");
                
                // Gemini API URL
                var apiUrl = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent";
                
                // Build Gemini request
                var requestBody = new
                {
                    contents = new[] 
                    { 
                        new 
                        { 
                            parts = new[] 
                            { 
                                new { text = prompt } 
                            } 
                        } 
                    },
                    generationConfig = new
                    {
                        maxOutputTokens = 500
                    }
                };

                var requestJson = JsonConvert.SerializeObject(requestBody);
                using var requestContent = new StringContent(requestJson, Encoding.UTF8, "application/json");
                
                // Add the API key as a query parameter
                var requestUrl = $"{apiUrl}?key={geminiKey}";
                
                var response = await _httpClient.PostAsync(requestUrl, requestContent);
                var responseJson = await response.Content.ReadAsStringAsync();

                dynamic responseObj = JsonConvert.DeserializeObject(responseJson);
                analysis = responseObj.candidates[0].content.parts[0].text;
            }
            else
            {
                var openaiKey = Environment.GetEnvironmentVariable("AZURE_OPENAI_KEY");
                var openaiEndpoint = Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT");
                var apiUrl = $"{openaiEndpoint}/openai/deployments/gpt-4-turbo/chat/completions?api-version=2023-03-15-preview";

                var requestBody = new
                {
                    messages = new[] { new { role = "user", content = prompt } },
                    max_tokens = 500
                };

                var requestJson = JsonConvert.SerializeObject(requestBody);
                using var requestContent = new StringContent(requestJson, Encoding.UTF8, "application/json");
                requestContent.Headers.Add("api-key", openaiKey);

                var response = await _httpClient.PostAsync(apiUrl, requestContent);
                var responseJson = await response.Content.ReadAsStringAsync();

                dynamic responseObj = JsonConvert.DeserializeObject(responseJson);
                analysis = responseObj.choices[0].message.content;
            }
            
            logger.LogInformation("Security Analysis: " + analysis);
            return analysis;
        }

        private async Task<dynamic> RunContentModerationAsync(string text, ILogger logger)
        {
            var moderatorEndpoint = Environment.GetEnvironmentVariable("AZURE_CONTENT_MODERATOR_ENDPOINT");
            var moderatorKey = Environment.GetEnvironmentVariable("AZURE_CONTENT_MODERATOR_KEY");
            var url = $"{moderatorEndpoint}/contentmoderator/moderate/v1.0/ProcessText/Screen";

            using var content = new StringContent(text, Encoding.UTF8, "text/plain");
            content.Headers.Add("Ocp-Apim-Subscription-Key", moderatorKey);

            var response = await _httpClient.PostAsync(url, content);
            var responseJson = await response.Content.ReadAsStringAsync();
            logger.LogInformation("Content Moderation Result: " + responseJson);
            return JsonConvert.DeserializeObject(responseJson);
        }
    }
}
