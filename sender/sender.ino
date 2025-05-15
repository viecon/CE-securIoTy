#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <WiFi.h>

#include "mbedtls/base64.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/rsa.h"

// ===== 使用者設定區域 =====
const char *ssid = "ED417C";
const char *password = "4172417@";

const char *KMS_IP = "192.168.50.57";
const int KMS_PORT = 5000;
const char *REG_PATH = "/api/registration";
const char *TOKEN_PATH = "/api/token";
const char *PUBKEY_PATH = "/api/publicKey";

const char *DB_IP = "192.168.50.57";
const int DB_PORT = 8080;
const char *MORSECODE_PATH = "/morsecode";

const char *UUID = "CE";
const char *PASSPHRASE = "NMSL";

// AES-256-GCM Key & 固定 Nonce（對應 Python 範例）
#define AES_KEY_BYTES 32
static const uint8_t AES_KEY[AES_KEY_BYTES] = {
    'Y', 'o', 'u', 'r', 'P', 'Y', 'i', 's', 'A', 'L', 'i',
    't', 't', 'l', 'e', 'S', 'p', 'a', 'r', 's', 'e', '0',
    '0', '0', '0', '0', '0', '0', '0', '0', '0', '1'};
static const uint8_t GCM_IV[12] = {'1', '2', '3', '4', '5', '6',
                                   '1', '2', '3', '4', '5', '6'};
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

// 按鈕 & LED
const int START_BUTTON_PIN = 4;
const int RECORD_BUTTON_PIN = 2;
const int LED_PIN = 13;

const unsigned long SAMPLE_INTERVAL = 2000;
const int MAX_BITS = 8;

// mbedTLS DRBG
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

// 通訊用
String authToken;
std::vector<String> queries, pub_ns, pub_es;

// 函式原型
bool connectToWiFi();
bool initDrbg();
bool performRegistration();
bool getAuthToken();
bool getPublicKeys();
void collectAndSendmorseCode();
String encryptGcmBase64(const String &pt);
String rsaEncryptKeyBase64(const String &hexN, const String &hexE);

// ===== setup & loop =====
void setup() {
  Serial.begin(115200);
  pinMode(START_BUTTON_PIN, INPUT);
  pinMode(RECORD_BUTTON_PIN, INPUT);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  // 1) 連WiFi
  if (!connectToWiFi())
    while (1)
      delay(500);

  // 2) 初始化DRBG
  if (!initDrbg())
    while (1)
      delay(500);

  // 3) 註冊
  if (!performRegistration()) {
    Serial.println("Registration failed"); // while(1) delay(500);
  }
  // 4) 取Token
  if (!getAuthToken()) {
    Serial.println("Get Token failed"); // while(1) delay(500);
  }
  Serial.println("AuthToken: " + authToken);

  // 5) 查公鑰
  queries = {"godempty"};
  if (!getPublicKeys()) {
    Serial.println("Fetch public keys failed"); // while(1) delay(500);
  }
  Serial.printf("Got %d public keys\n", pub_ns.size());
}

void loop() {
  // 等START按鈕 LOW→HIGH 觸發
  Serial.println("Here");
  static bool lastState = LOW;
  bool cur = digitalRead(START_BUTTON_PIN);
  if (cur == HIGH && lastState == LOW) {
    collectAndSendmorseCode();
    while (digitalRead(START_BUTTON_PIN) == HIGH)
      delay(10);
    Serial.println("END");
  }
  lastState = cur;
  delay(3000);
}

// ===== 功能函式 =====

bool connectToWiFi() {
  WiFi.begin(ssid, password);
  for (int i = 0; i < 30; i++) {
    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("WiFi: " + WiFi.localIP().toString());
      return true;
    }
    delay(500);
  }
  return false;
}

bool initDrbg() {
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  return mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)"morse-app",
                               strlen("morse-app")) == 0;
}

bool performRegistration() {
  HTTPClient http;
  String url = String("http://") + KMS_IP + ":" + KMS_PORT + REG_PATH;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  DynamicJsonDocument d(256);
  d["uuid"] = UUID;
  d["passphrase"] = PASSPHRASE;
  String b;
  serializeJson(d, b);
  int code = http.POST(b);
  http.end();

  Serial.printf("Reg error: %d\n", code);
  return (code == 200 || code == 201);
}

bool getAuthToken() {
  HTTPClient http;
  String url = String("http://") + KMS_IP + ":" + KMS_PORT + TOKEN_PATH;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  DynamicJsonDocument d(256);
  d["uuid"] = UUID;
  d["passphrase"] = PASSPHRASE;
  String b;
  serializeJson(d, b);
  int code = http.POST(b);
  if (code == 200) {
    String r = http.getString();
    DynamicJsonDocument rd(256);
    deserializeJson(rd, r);
    authToken = rd["token"].as<String>();
    http.end();
    return true;
  }
  http.end();
  return false;
}

bool getPublicKeys() {
  // JSON body
  DynamicJsonDocument d(256);
  JsonArray arr = d.createNestedArray("queries");
  for (auto &q : queries)
    arr.add(q);
  String b;
  serializeJson(d, b);

  HTTPClient http;
  String url = String("http://") + KMS_IP + ":" + KMS_PORT + PUBKEY_PATH;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  int code = http.sendRequest("POST", (uint8_t *)b.c_str(), b.length());
  if (code != 200) {
    http.end();
    return false;
  }

  String r = http.getString();
  http.end();
  DynamicJsonDocument rd(512);
  if (deserializeJson(rd, r))
    return false;
  JsonArray na = rd["ns"], ea = rd["es"];
  if (na.size() != ea.size())
    return false;
  pub_ns.clear();
  pub_es.clear();
  for (size_t i = 0; i < na.size(); i++) {
    pub_ns.push_back(na[i].as<String>());
    pub_es.push_back(ea[i].as<String>());
  }
  return true;
}

void collectAndSendmorseCode() {
  // 收8bit
  String bits;
  for (int i = 0; i < MAX_BITS; i++) {
    bool p = (digitalRead(RECORD_BUTTON_PIN) == HIGH);
    bits += (p ? '1' : '0');
    digitalWrite(LED_PIN, p ? HIGH : LOW);
    delay(SAMPLE_INTERVAL);
    Serial.println("Point Taken " + p);
  }
  digitalWrite(LED_PIN, LOW);
  Serial.println("Bits: " + bits);

  // AES-GCM + Base64
  String code64 = encryptGcmBase64(bits);

  // RSA(PKCS1_v1.5) 加密 AES_KEY → Base64
  std::vector<String> encKeys;
  for (size_t i = 0; i < pub_ns.size(); i++) {
    encKeys.push_back(rsaEncryptKeyBase64(pub_ns[i], pub_es[i]));
  }

  // 組 JSON & POST
  DynamicJsonDocument d(1024);
  d["uuid"] = UUID;
  JsonArray ua = d.createNestedArray("uuids");
  for (auto &q : queries)
    ua.add(q);
  JsonArray ka = d.createNestedArray("keys");
  for (auto &k : encKeys)
    ka.add(k);
  d["token"] = authToken;
  d["code"] = code64;

  Serial.println("---- JSON Payload ----");
  serializeJsonPretty(d, Serial);
  Serial.println();
  Serial.println("----------------------");

  String b;
  serializeJson(d, b);
  HTTPClient http;
  String url = String("http://") + DB_IP + ":" + DB_PORT + MORSECODE_PATH;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(b);
  Serial.printf("POST /morsecode→%d\n", code);
  if (code == 200)
    Serial.println("OK");
  http.end();
}

// AES-GCM 固定IV + Base64
String encryptGcmBase64(const String &pt) {
  // GCM
  mbedtls_gcm_context g;
  mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, AES_KEY, 256);
  size_t L = pt.length();
  uint8_t ct[L], tag[GCM_TAG_LEN];
  mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, L, GCM_IV, GCM_IV_LEN,
                            NULL, 0, (const uint8_t *)pt.c_str(), ct,
                            GCM_TAG_LEN, tag);
  mbedtls_gcm_free(&g);

  // 拼 IV|CT|TAG
  size_t tot = GCM_IV_LEN + L + GCM_TAG_LEN;
  uint8_t *buf = (uint8_t *)malloc(tot);
  memcpy(buf, GCM_IV, GCM_IV_LEN);
  memcpy(buf + GCM_IV_LEN, ct, L);
  memcpy(buf + GCM_IV_LEN + L, tag, GCM_TAG_LEN);

  // Base64
  size_t out_len, sz = 4 * ((tot + 2) / 3) + 1;
  char *b = (char *)malloc(sz);
  mbedtls_base64_encode((unsigned char *)b, sz, &out_len, buf, tot);
  b[out_len] = 0;
  String r(b);
  free(buf);
  free(b);
  return r;
}

// RSA 公鑰加密 AES_KEY → Base64
String rsaEncryptKeyBase64(const String &hexN, const String &hexE) {
  mbedtls_mpi N, E;
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);
  mbedtls_mpi_read_string(&N, 16, hexN.c_str());
  mbedtls_mpi_read_string(&E, 16, hexE.c_str());

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E);
  mbedtls_rsa_complete(&rsa);
  rsa.len = mbedtls_mpi_size(&N);

  // Encrypt
  uint8_t outBuf[MBEDTLS_MPI_MAX_SIZE];
  mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
                            MBEDTLS_RSA_PUBLIC, AES_KEY_BYTES, AES_KEY, outBuf);

  // Base64
  size_t out_len, sz = 4 * ((rsa.len + 2) / 3) + 1;
  char *b = (char *)malloc(sz);
  mbedtls_base64_encode((unsigned char *)b, sz, &out_len, outBuf, rsa.len);
  b[out_len] = 0;
  String r(b);
  free(b);

  mbedtls_rsa_free(&rsa);
  mbedtls_mpi_free(&N);
  mbedtls_mpi_free(&E);
  return r;
}
