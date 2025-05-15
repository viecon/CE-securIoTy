#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h" // 如果使用 AES-GCM 模式
#include "mbedtls/md.h"  // 如果需要生成隨機數或進行哈希
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"

#define led_pin 25
#define btn_pin 19
// 引入必要的庫 (根據你的開發板和需求調整)
#include <WiFi.h>         // 或者 ESP8266WiFi.h
#include <HTTPClient.h>   // 或者 ESP8266HTTPClient.h
#include <ArduinoJson.h>  // 用於解析和生成 JSON
#include <WebServer.h>

// --- 全域變數和常量 ---
const char* ssid = "ED417C";
const char* password = "4172417@";

const char* kmsServerAddress = "192.168.50.57"; // KMS 伺服器地址
const int kmsPort = 5000; // HTTPS 預設端口
const char* kmsRegistration = "/api/registration";
const char* kmsTokenEndpoint = "/api/token";
const char* kmsDecryptEndpoint = "/api/decrypt";

const char* dataServerAddress = "192.168.50.57"; // 資料伺服器地址
const int dataPort = 8080;
const char* dataFetchEndpoint = "/morsecode/get"; // 假設獲取資料的端點
const char* dataGetListEndpoint = "/getList";

String userUUID = "godempty";         // 你的用戶 ID
String userPassphrase = "114514"; // 你的通關密語

String authToken = "";
String encryptedSenderKey_base64 = ""; // 從資料伺服器獲取的加密的送方金鑰 (Base64)
String encryptedFile_base64 = "";    // 從資料伺服器獲取的加密的檔案 (Base64)
u_int8_t n;
size_t n_size;
u_int8_t e;
size_t e_size;

// --- Web Server ---
WebServer server(80);

// --- Global Variable to store the chosen file ---
String chosenFileName = "None";

// AES 加密/解密相關 (假設 AES-256-GCM)
#define AES_KEY_SIZE 256
#define AES_KEY_BYTES (AES_KEY_SIZE / 8)
#define GCM_IV_LENGTH 12 // GCM 推薦的 IV 長度
#define GCM_TAG_LENGTH 16 // GCM 認證標籤長度

uint8_t decryptedSenderKey[AES_KEY_BYTES];
size_t decryptedSenderKeyLength = 0;

// mbedtls 隨機數生成器上下文 (如果需要生成 IV)
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
const char *personalization = "my-aes-gcm-app"; // 個性化字符串

// --- 函數聲明 (Function Prototypes) ---
bool connectToWiFi();
bool initializeRandomGenerator();
bool getAuthTokenFromKMS(const String& uuid, const String& passphrase, String& token);
bool fetchDataFromServer(const String& uuid, const String& token, String& encKeyBase64, String& encFileBase64); // 假設伺服器返回的 encryptedFile_base64 包含 IV+Ciphertext+Tag
bool getDecryptedSenderKeyFromKMS(const String& token, const String& uuid, const String& passphrase, const String& encryptedKeyBase64, uint8_t* decryptedKey, size_t& keyLength);
bool decryptFileAES_GCM(const uint8_t* key, size_t keyLen, const String& encryptedFileWithIvTagBase64, String& decryptedContent);
bool performRegistration(const String& uuid, const String& passphrase,
                         uint8_t* n_out_bytes, size_t max_n_len, size_t& n_len_out,
                         uint8_t* e_out_bytes, size_t max_e_len, size_t& e_len_out);
void clearSensitiveData();

// --- WebServer Shit ---
void handleRoot() {
  // Using a C++ Raw String Literal for HTML and embedded JavaScript
  String htmlTemplate = R"HTML_PAGE(
<!DOCTYPE html>
<html>
<head>
  <title>ESP32 File Selector</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
    h1 { color: #007bff; }
    .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    label { display: block; margin-bottom: 8px; font-weight: bold; }
    select, input[type='submit'] { padding: 10px; margin-bottom: 20px; border-radius: 4px; border: 1px solid #ddd; width: calc(100% - 22px); }
    input[type='submit'] { background-color: #28a745; color: white; cursor: pointer; width: auto; }
    input[type='submit']:hover { background-color: #218838; }
    .status { margin-top: 20px; padding: 10px; background-color: #e9ecef; border-left: 5px solid #007bff; }
    #api_status { margin-bottom: 15px; font-style: italic; }
  </style>
</head>
<body>
  <div class="container">
    <h1>ESP32 File Selector</h1>
    <p>Requesting file list for UUID: <strong>%%DEVICE_UUID_DISPLAY%%</strong></p>
    <div id="api_status">Fetching list from API...</div>

    <form method="POST" action="/selectFile">
      <label for="file_select">Choose a file:</label>
      <select name="selected_file_name" id="file_select" required>
        <option value="" disabled selected>Loading files...</option>
      </select><br><br>
      <input type="submit" value="Select This File">
    </form>

    <div class="status">Lastly chosen file: <strong>%%CHOSEN_FILE_NAME%%</strong></div>

    <script>
      const R_UUID = '%%DEVICE_UUID_JS%%';
      const R_API_HOST = '%%PYTHON_API_HOST_JS%%';
      const R_API_PORT = %%PYTHON_API_PORT_JS%%; // This will be a number, so no quotes in JS
      const R_API_ENDPOINT = '%%PYTHON_API_ENDPOINT_JS%%';

      document.addEventListener('DOMContentLoaded', function() {
        const selectElement = document.getElementById('file_select');
        const apiStatusElement = document.getElementById('api_status');
        const apiUrl = `http://${R_API_HOST}:${R_API_PORT}${R_API_ENDPOINT}`;

        console.log("Attempting to fetch from: " + apiUrl + " with UUID: " + R_UUID);

        fetch(apiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ uuid: R_UUID })
        })
        .then(response => {
          if (!response.ok) {
            return response.text().then(text => { 
              // Try to parse as JSON for a structured error message from API
              try {
                  const errData = JSON.parse(text);
                  throw new Error(`API Error ${response.status}: ${errData.error || errData.message || text}`);
              } catch (e) {
                  throw new Error(`API Error ${response.status}: ${text}`);
              }
            });
          }
          return response.json();
        })
        .then(data => {
          console.log("API Response Data:", data);
          selectElement.innerHTML = ''; // Clear loading/error options
          if (data.files && data.files.length > 0) {
            data.files.forEach(fileName => {
              const option = document.createElement('option');
              option.value = fileName;
              option.textContent = fileName;
              selectElement.appendChild(option);
            });
            apiStatusElement.textContent = 'File list loaded successfully.';
            selectElement.disabled = false;
          } else {
            const message = data.message || 'No files found for this UUID or API returned an empty list.';
            selectElement.innerHTML = `<option value="" disabled selected>${message}</option>`;
            apiStatusElement.textContent = message;
            selectElement.disabled = true;
          }
        })
        .catch(error => {
          console.error('Error fetching file list:', error);
          apiStatusElement.textContent = 'Error fetching file list: ' + error.message;
          selectElement.innerHTML = '<option value="" disabled selected>Error loading files.</option>';
          selectElement.disabled = true;
        });
      });
    </script>
  </div>
</body>
</html>
)HTML_PAGE";

  String htmlOutput = htmlTemplate; // Create a mutable copy

  // Replace placeholders with actual values
  htmlOutput.replace("%%CHOSEN_FILE_NAME%%", chosenFileName);
  htmlOutput.replace("%%DEVICE_UUID_DISPLAY%%", String(userUUID));
  htmlOutput.replace("%%DEVICE_UUID_JS%%", String(userUUID));
  htmlOutput.replace("%%PYTHON_API_HOST_JS%%", String(dataServerAddress));
  htmlOutput.replace("%%PYTHON_API_PORT_JS%%", String(dataPort)); // Converts int to String
  htmlOutput.replace("%%PYTHON_API_ENDPOINT_JS%%", String(dataGetListEndpoint));

  server.send(200, "text/html", htmlOutput);
}

void SendAndFlash(){
  String s = runSecureDataRetrieval();
  if(s != ""){
    int sz = s.length();
    for(int i = 0 ; i < sz ; ++i){
      if(s[i] == '1') digitalWrite(led_pin, HIGH);
      else digitalWrite(led_pin, LOW);
      delay(100);
    }
  }
}

void handleFileSelection() {
  if (server.hasArg("selected_file_name")) {
    chosenFileName = server.arg("selected_file_name");
    Serial.print("File selected by user: ");
    Serial.println(chosenFileName);
    SendAndFlash();
    delay(1000);
    server.sendHeader("Location", "/");
    server.send(303);
    return;
  }
  server.send(400, "text/plain", "400: Bad Request - No file selected");
}

void handleNotFound() {
  server.send(404, "text/plain", "404: Not found");
}
// --- Arduino 標準函數 ---
void setup() {
  Serial.begin(115200);
  while (!Serial);
  pinMode(led_pin,OUTPUT);
  pinMode(btn_pin,INPUT);
  Serial.println("Initializing (HTTP, AES with mbedtls)...");
  
  if (!connectToWiFi()) {
    Serial.println("Failed to connect to WiFi. Halting.");
    while (true);
  }
  Serial.println("WiFi Connected.");
  server.on("/", HTTP_GET, handleRoot);
  server.on("/selectFile", HTTP_POST, handleFileSelection);
  server.onNotFound(handleNotFound);

  server.begin();
  if (!initializeRandomGenerator()) {
      Serial.println("Failed to initialize mbedtls random generator. Halting.");
      while(true);
  }
  Serial.println("mbedtls random generator initialized.");

  if(!performRegistration(userUUID,userPassphrase,&n,static_cast<size_t>(128),n_size,&e,12,e_size)){
    Serial.println("Failed to registration");
  }
  delay(500);
}

int prev_state=0, curr_state=0;
void loop() {
  server.handleClient();
  curr_state = digitalRead(btn_pin);
  if(curr_state==LOW && prev_state == HIGH){
    
  }
  prev_state = curr_state;
}

// --- 主流程函數 ---
String runSecureDataRetrieval() {
  Serial.println("\n--- Starting Secure Data Retrieval Process (HTTP) ---");
  
  if (!getAuthTokenFromKMS(userUUID, userPassphrase, authToken)) {
    Serial.println("Failed to get Auth Token from KMS.");
    return "";
  }
  Serial.print("Auth Token received: "); Serial.println(authToken);
  delay(500);
  if (!fetchDataFromServer(userUUID, authToken, encryptedSenderKey_base64, encryptedFile_base64)) {
    Serial.println("Failed to fetch data from server.");
    return "";
  }
  Serial.println("Encrypted data and key received from server.");
  delay(500);
  if (!getDecryptedSenderKeyFromKMS(authToken, userUUID, userPassphrase, encryptedSenderKey_base64, decryptedSenderKey, decryptedSenderKeyLength)) {
    Serial.println("Failed to get decrypted sender key from KMS.");
    clearSensitiveData();
    return "";
  }
  Serial.println("Sender key decrypted successfully.");
  if (decryptedSenderKeyLength != AES_KEY_BYTES) {
      Serial.printf("Decrypted key length mismatch! Expected %d, got %d\n", AES_KEY_BYTES, decryptedSenderKeyLength);
      clearSensitiveData();
      return "";
  }

  delay(500);
  String decryptedFileContent = "";
  if (!decryptFileAES_GCM(decryptedSenderKey, decryptedSenderKeyLength, encryptedFile_base64, decryptedFileContent)) {
    Serial.println("Failed to decrypt file.");
    clearSensitiveData();
    return "";
  }
  delay(1000);  
  Serial.println("File decrypted successfully!");
  Serial.println("--- Decrypted File Content ---");
  Serial.println(decryptedFileContent);
  Serial.println("-----------------------------");

  clearSensitiveData();
  Serial.println("--- Secure Data Retrieval Process Finished ---");
  return decryptedFileContent;
}

// --- 輔助函數實現 ---

bool connectToWiFi() { /* 與之前版本相同 */
  Serial.print("Connecting to WiFi SSID: ");
  Serial.println(ssid);
  WiFi.begin(ssid, password);
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) { // 嘗試連接10秒
    delay(500);
    Serial.print(".");
    attempts++;
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWiFi connected!");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
    return true;
  } else {
    Serial.println("\nFailed to connect to WiFi.");
    return false;
  }
}

bool initializeRandomGenerator() {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *)personalization,
                                   strlen(personalization));
    if (ret != 0) {
        Serial.printf("mbedtls_ctr_drbg_seed failed: -0x%04X\n", -ret);
        return false;
    }
    return true;
}

bool getAuthTokenFromKMS(const String& uuid, const String& passphrase, String& token) {
  if (WiFi.status() != WL_CONNECTED) return false;

  HTTPClient http;
  String serverPath = "http://" + String(kmsServerAddress) + ":" + String(kmsPort) + String(kmsTokenEndpoint);
  Serial.print("KMS Auth URL: "); Serial.println(serverPath);

  if (!http.begin(serverPath)) {
      Serial.println("HTTPClient.begin (KMS Auth) failed");
      return false;
  }
  http.addHeader("Content-Type", "application/json");

  DynamicJsonDocument doc(256); // 調整 JSON 文檔大小
  doc["uuid"] = uuid;
  doc["passphrase"] = passphrase;
  String requestBody;
  serializeJson(doc, requestBody);
  delay(1000);
  Serial.print("KMS Auth Request: "); Serial.println(requestBody);
  int httpResponseCode = http.POST(requestBody);

  if (httpResponseCode == HTTP_CODE_OK) {
    String payload = http.getString();
    Serial.print("KMS Auth Response: "); Serial.println(payload);
    DynamicJsonDocument responseDoc(256); // 調整大小
    DeserializationError error = deserializeJson(responseDoc, payload);
    if (error) {
      Serial.print("deserializeJson() failed: ");
      Serial.println(error.c_str());
      http.end();
      return false;
    }
    if (responseDoc.containsKey("token")) {
      token = responseDoc["token"].as<String>();
      http.end();
      return true;
    } else {
      Serial.println("Token not found in KMS response.");
    }
  } else {
    Serial.print("KMS Auth Error code: ");
    Serial.println(httpResponseCode);
    String payload = http.getString();
    Serial.println("Error payload: " + payload);
  }
  http.end();
  return false;
}

bool fetchDataFromServer(const String& uuid, const String& token, String& encKeyBase64, String& encFileBase64) {
  if (WiFi.status() != WL_CONNECTED || token.isEmpty()) return false;
  HTTPClient http;
  String serverPath = "http://" + String(dataServerAddress) + ":" + String(dataPort) + String(dataFetchEndpoint);
  if (!http.begin(serverPath)) {
      Serial.println("HTTPClient.begin (Fetch Data) failed");
      return false;
  }
  http.addHeader("Content-Type", "application/json");

  DynamicJsonDocument doc(512); // 調整 JSON 文檔大小
  doc["file_name"] = chosenFileName;
  doc["uuid"] = uuid;
  doc["token"] = token;
  String requestBody;
  serializeJson(doc, requestBody);
  delay(1000);
  Serial.println("Fetching data from server...");
  Serial.println("Body:"); Serial.println(requestBody);
  int httpResponseCode = http.POST(requestBody);
  if (httpResponseCode == HTTP_CODE_OK) {
    String payload = http.getString();
    Serial.print("Server Data Response: "); Serial.println(payload); // 可能很長
    DynamicJsonDocument responseDoc(ESP.getMaxAllocHeap() / 4); // 嘗試分配較大空間，注意內存
    DeserializationError error = deserializeJson(responseDoc, payload);
    if (error) {
      Serial.print("deserializeJson() failed for data: "); Serial.println(error.c_str());
      http.end();
      return false;
    }
    if (responseDoc.containsKey("encryptedKey") && responseDoc.containsKey("encryptedFile")) {
      encKeyBase64 = responseDoc["encryptedKey"].as<String>();
      encFileBase64 = responseDoc["encryptedFile"].as<String>();
      http.end();
      return true;
    } else {
      Serial.println("Required keys (encryptedKey, encryptedFile) not found in server response.");
    }
  } else {
    Serial.print("Fetch Data Error code: "); Serial.println(httpResponseCode);
    String payload = http.getString(); Serial.println("Error payload: " + payload);
  }
  http.end();
  return false;
}


bool getDecryptedSenderKeyFromKMS(const String& token, const String& uuid, const String& passphrase, const String& encryptedKeyBase64, uint8_t* decryptedKey, size_t& keyLength) {
  if (WiFi.status() != WL_CONNECTED || token.isEmpty() || encryptedKeyBase64.isEmpty()) return false;
  HTTPClient http;
  String serverPath = "http://" + String(kmsServerAddress) + ":" + String(kmsPort) + String(kmsDecryptEndpoint);
  if (!http.begin(serverPath)) {
      Serial.println("HTTPClient.begin (KMS Decrypt) failed");
      return false;
  }
  http.addHeader("Content-Type", "application/json");

  DynamicJsonDocument doc(512);
  doc["token"] = token;
  doc["uuid"] = uuid;
  doc["passphrase"] = passphrase; // 再次確認是否需要
  doc["encryptedKey"] = encryptedKeyBase64;
  String requestBody;
  serializeJson(doc, requestBody);
  delay(500);
  Serial.print("KMS Decrypt Request: "); Serial.println(requestBody);
  int httpResponseCode = http.POST(requestBody);

  if (httpResponseCode == HTTP_CODE_OK) {
    String payload = http.getString();
    Serial.print("KMS Decrypt Response: "); Serial.println(payload);
    DynamicJsonDocument responseDoc(512);
    DeserializationError error = deserializeJson(responseDoc, payload);
    if (error) {
      Serial.print("deserializeJson() failed for key decrypt: "); Serial.println(error.c_str());
      http.end();
      return false;
    }
    if (responseDoc.containsKey("decryptedSenderKey")) { // 假設返回的是 Base64 編碼的 byte array
      String keyBase64 = responseDoc["decryptedSenderKey"].as<String>();
      size_t decodedLen = 0;
      // 預估解碼後的長度，確保緩衝區足夠
      // Base64 解碼: 輸出長度約為輸入長度的 3/4
      size_t bufferSize = keyBase64.length() * 3 / 4 + 4; // 加一點餘量
      if (bufferSize > AES_KEY_BYTES) bufferSize = AES_KEY_BYTES; // 不要超過我們的目標金鑰長度

      int ret = mbedtls_base64_decode(decryptedKey, bufferSize, &decodedLen, (const unsigned char*)keyBase64.c_str(), keyBase64.length());
      if (ret == 0 && decodedLen > 0) {
          keyLength = decodedLen;
          http.end();
          return true;
      } else {
          Serial.printf("mbedtls_base64_decode failed or zero length: -0x%04X, len: %d\n", -ret, decodedLen);
      }
    } else {
      Serial.println("decryptedSenderKey not found in KMS response.");
    }
  } else {
    Serial.print("KMS Decrypt Error code: "); Serial.println(httpResponseCode);
    String payload = http.getString(); Serial.println("Error payload: " + payload);
  }
  http.end();
  return false;
}


/**
 * @brief 使用 AES-GCM 解密檔案
 * @param key 解密後的送方金鑰 (AES_KEY_BYTES 長度)
 * @param keyLen 金鑰長度 (應為 AES_KEY_BYTES)
 * @param encryptedFileWithIvTagBase64 Base64 編碼的 (IV + Ciphertext + Tag)
 * @param decryptedContent (輸出) 解密後的檔案內容
 * @return true 如果成功解密, false 否則
 */
bool decryptFileAES_GCM(const uint8_t* key, size_t keyLen, const String& encryptedFileWithIvTagBase64, String& decryptedContent) {
  if (key == nullptr || keyLen != AES_KEY_BYTES || encryptedFileWithIvTagBase64.isEmpty()) {
    Serial.println("decryptFileAES_GCM: Invalid parameters.");
    return false;
  }

  mbedtls_gcm_context gcm_ctx;
  int ret;

  // 1. Base64 解碼 encryptedFileWithIvTagBase64
  size_t b64DecodedLen = 0;
  size_t b64InputLen = encryptedFileWithIvTagBase64.length();
  // 預估解碼後長度
  size_t maxDecodedBufSize = b64InputLen * 3 / 4 + 4;
  unsigned char* combined_data = (unsigned char*)malloc(maxDecodedBufSize);
  if (!combined_data) {
    Serial.println("Failed to allocate memory for combined_data.");
    return false;
  }

  ret = mbedtls_base64_decode(combined_data, maxDecodedBufSize, &b64DecodedLen,
                              (const unsigned char*)encryptedFileWithIvTagBase64.c_str(), b64InputLen);
  if (ret != 0 || b64DecodedLen < (GCM_IV_LENGTH + GCM_TAG_LENGTH)) { // 至少要有 IV 和 Tag
    Serial.printf("mbedtls_base64_decode failed or decoded data too short: -0x%04X, len: %d\n", -ret, b64DecodedLen);
    free(combined_data);
    return false;
  }

  // 2. 分離 IV, Ciphertext, Tag
  // 假設順序是 IV (12 bytes) | Ciphertext (variable) | Tag (16 bytes)
  const unsigned char* iv = combined_data;
  const unsigned char* ciphertext = combined_data + GCM_IV_LENGTH;
  size_t ciphertext_len = b64DecodedLen - GCM_IV_LENGTH - GCM_TAG_LENGTH;
  const unsigned char* tag = combined_data + GCM_IV_LENGTH + ciphertext_len;

  if (ciphertext_len <= 0) { // 應該 ciphertext_len >=0 (可以是空內容)
      Serial.println("Ciphertext length is zero or negative after parsing.");
      free(combined_data);
      return false;
  }


  // 3. 初始化 GCM 上下文並設置金鑰
  mbedtls_gcm_init(&gcm_ctx);
  ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE); // 金鑰長度用 bits
  if (ret != 0) {
    Serial.printf("mbedtls_gcm_setkey failed: -0x%04X\n", -ret);
    mbedtls_gcm_free(&gcm_ctx);
    free(combined_data);
    return false;
  }

  // 4. 執行解密和認證
  // 預分配解密後文本的緩衝區，與密文等長或稍大
  unsigned char* plaintext_buf = (unsigned char*)malloc(ciphertext_len + 1); // +1 for null terminator for string
  if (!plaintext_buf) {
    Serial.println("Failed to allocate memory for plaintext_buf.");
    mbedtls_gcm_free(&gcm_ctx);
    free(combined_data);
    return false;
  }

  ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, ciphertext_len,
                                 iv, GCM_IV_LENGTH,
                                 NULL, 0, // Additional Authenticated Data (AAD), 如果有的話
                                 tag, GCM_TAG_LENGTH,
                                 ciphertext, plaintext_buf);

  if (ret == 0) { // 解密和認證成功
    plaintext_buf[ciphertext_len] = '\0'; // 添加字符串結束符
    decryptedContent = String((char*)plaintext_buf);
    Serial.println("AES-GCM decryption successful.");
  } else {
    Serial.printf("mbedtls_gcm_auth_decrypt failed: -0x%04X (Tag mismatch or other error)\n", -ret);
    decryptedContent = "";
  }

  mbedtls_gcm_free(&gcm_ctx);
  free(combined_data);
  free(plaintext_buf);
  return (ret == 0);
}


bool performRegistration(const String& uuid, const String& passphrase,
                         uint8_t* n_out_bytes, size_t max_n_len, size_t& n_len_out,
                         uint8_t* e_out_bytes, size_t max_e_len, size_t& e_len_out) {
  if (WiFi.status() != WL_CONNECTED) return false;

  HTTPClient http;
  String serverPath = "http://" + String(kmsServerAddress) + ":" + String(kmsPort) + String(kmsRegistration);
  Serial.print("KMS Registration URL: "); Serial.println(serverPath);

  if (!http.begin(serverPath)) {
      Serial.println("HTTPClient.begin (KMS Registration) failed");
      return false;
  }
  http.addHeader("Content-Type", "application/json");

  DynamicJsonDocument doc(256);
  doc["uuid"] = uuid;
  doc["passphrase"] = passphrase;
  String requestBody;
  serializeJson(doc, requestBody);
  delay(500);
  Serial.print("KMS Registration Request: "); Serial.println(requestBody);
  int httpResponseCode = http.POST(requestBody);

  if (httpResponseCode == HTTP_CODE_OK || httpResponseCode == HTTP_CODE_CREATED) {
    String payload = http.getString();
    Serial.print("KMS Registration Response: "); Serial.println(payload);
    DynamicJsonDocument responseDoc(1024); 
    DeserializationError error = deserializeJson(responseDoc, payload);
    if (error) {
      Serial.print("deserializeJson() failed for registration: ");
      Serial.println(error.c_str());
      http.end();
      return false;
    }
    if (responseDoc.containsKey("n") && responseDoc.containsKey("e")) {
      String hex_n_str = responseDoc["n"].as<String>();
      String hex_e_str = responseDoc["e"].as<String>();

      Serial.print("Received Hex N: "); Serial.println(hex_n_str);
      Serial.print("Received Hex E: "); Serial.println(hex_e_str);

      http.end();
      return true;
    } else {
      Serial.println("Public key 'n' or 'e' not found in KMS registration response.");
    }
  } else {
    Serial.print("KMS Registration Error code: ");
    Serial.println(httpResponseCode);
    String payload = http.getString();
    Serial.println("Error payload: " + payload);
  }
  http.end();
  return false;
}

void clearSensitiveData() {
  Serial.println("Clearing sensitive data from memory (HTTP)...");
  authToken = "";
  encryptedSenderKey_base64 = "";
  encryptedFile_base64 = "";
  // 更徹底的做法是覆蓋數組內容
  for (size_t i = 0; i < sizeof(decryptedSenderKey); ++i) {
    decryptedSenderKey[i] = 0x00;
  }
  decryptedSenderKeyLength = 0;
  // userPassphrase 也應該在使用後考慮清除，但如果每次都需要輸入則不同
  // userPassphrase = ""; // 取決於你的應用邏輯
}