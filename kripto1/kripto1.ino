//Bu kod, ESP32 mikrodenetleyicisi ve nRF24L01 kablosuz modülü kullanılarak geliştirilmiş, 
//AES-128 şifrelemeli, zaman senkronizasyonlu ve frekans atlamalı bir verici (TX) uygulamasıdır.
// Sistem ilk açılışta belirlenen senkronizasyon kanalı (Kanal 12 / 2412 MHz) üzerinden alıcı cihaz ile iletişim kurarak mikrosaniye hassasiyetindeki sistemin saatini paylaşır ve zaman senkronizasyonunu sağlar.
//Senkronizasyonun ardından dinlenmeyi ve sinyal karıştırmayı önlemek amacıyla belirlenen 8 farklı RF kanalı (10, 24, 28, 54, 77, 98, 1 ve 36) arasında 5 saniyede bir otomatik frekans atlaması gerçekleştirir.
//İletilecek veriler 32 baytlık paket yapısında düzenlenip mbedtls kütüphanesi aracılığıyla AES-128 ECB algoritmasıyla şifrelenir;
//Kanal değişim anlarındaki zaman kaymalarına karşı ise 20 ms'lik koruma aralığı (GUARD_US) uygulanarak iletim güvenilirliği artırılır.
#include <SPI.h>
#include <RF24.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "mbedtls/aes.h"

// Pin definitions
#define PIN_SCK   18
#define PIN_MISO  19
#define PIN_MOSI  23
#define PIN_CSN   5
#define PIN_CE    22

// Communication configuration
#define SYNC_CHANNEL 12          // 2412 MHz = 2400 + 12, used only for time sync
const byte TX_ADDRESS[6] = "1Node";   // Sender -> receiver
const byte RX_ADDRESS[6] = "2Node";   // Receiver -> sender
const uint8_t PAYLOAD_SIZE = 32;

// AES-128 key
const uint8_t AES_KEY[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// Frequency hopping configuration (must be identical on both devices)
const uint8_t CHANNELS[8] = {10, 24, 28, 54, 77, 98, 1, 36};
const uint8_t NUM_CHANNELS = sizeof(CHANNELS);
const int64_t HOP_INTERVAL_US = 5000000LL;   // Hop every 5 s
const int64_t GUARD_US = 20000LL;            // No TX within 20 ms of a slot boundary
const uint32_t SYNC_LINGER_MS = 1000;        // Keep answering sync requests for 1 s

// Packet types
#define PKT_SYNC_REQ   1
#define PKT_SYNC_RESP  2
#define PKT_DATA       3

// 32-byte packet layout (encrypted as 2 AES blocks)
struct __attribute__((packed)) Packet {
  uint8_t type;
  uint8_t channel;
  uint8_t reserved[2];
  int64_t timeUs;     // Sender system time in microseconds
  char text[20];
};

// RF24 radio instance: CE, CSN, 2 MHz SPI clock
RF24 radio(PIN_CE, PIN_CSN, 2000000UL);

Packet packet;
uint8_t encryptedBuffer[PAYLOAD_SIZE];  // Encrypted payload
uint8_t rxBuffer[PAYLOAD_SIZE];         // Received encrypted payload
uint32_t counter = 1;
uint8_t currentChannel = 255;

// Encrypt 32 bytes with AES-128 ECB
void aesEncryptECB(const uint8_t* in, uint8_t* out) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);
  for (uint8_t i = 0; i < PAYLOAD_SIZE; i += 16) {
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, in + i, out + i);
  }
  mbedtls_aes_free(&aes);
}

// Decrypt 32 bytes with AES-128 ECB
void aesDecryptECB(const uint8_t* in, uint8_t* out) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, AES_KEY, 128);
  for (uint8_t i = 0; i < PAYLOAD_SIZE; i += 16) {
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, in + i, out + i);
  }
  mbedtls_aes_free(&aes);
}

// System time in microseconds
int64_t nowUs() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
}

// Encrypt and send the global packet
void sendPacket() {
  aesEncryptECB((uint8_t*)&packet, encryptedBuffer);
  radio.write(encryptedBuffer, PAYLOAD_SIZE);
}

// Wait on the sync channel and answer sync requests with our system time
void timeSync() {
  radio.setChannel(SYNC_CHANNEL);
  radio.startListening();
  Serial.println("Waiting for sync request on 2412 MHz...");

  uint32_t lastAnswerMs = 0;
  bool answered = false;

  while (!answered || millis() - lastAnswerMs < SYNC_LINGER_MS) {
    if (!radio.available()) continue;

    radio.read(rxBuffer, PAYLOAD_SIZE);
    Packet req;
    aesDecryptECB(rxBuffer, (uint8_t*)&req);
    if (req.type != PKT_SYNC_REQ) continue;

    // Reply with the current system time
    radio.stopListening();
    memset(&packet, 0, sizeof(packet));
    packet.type = PKT_SYNC_RESP;
    packet.channel = SYNC_CHANNEL;
    packet.timeUs = nowUs();
    sendPacket();
    radio.startListening();

    answered = true;
    lastAnswerMs = millis();
    Serial.println("Sync request answered");
  }

  radio.stopListening();
  Serial.println("Time sync done, starting frequency hopping");
}

// Switch to the channel of the current time slot
void updateChannel() {
  int64_t slot = nowUs() / HOP_INTERVAL_US;
  uint8_t ch = CHANNELS[slot % NUM_CHANNELS];
  if (ch != currentChannel) {
    radio.setChannel(ch);
    currentChannel = ch;
    Serial.printf("Hop -> slot %lld, channel %u (%u MHz)\n", slot, ch, 2400 + ch);
  }
}

void setup() {
  // Start the serial port
  Serial.begin(115200);
  delay(500);

  // Initialize SPI on the defined pins
  SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI, PIN_CSN);

  // Check the module connection
  if (!radio.begin(&SPI) || !radio.isChipConnected()) {
    Serial.println("ERROR! nRF24L01 not detected!");
    while (1) delay(1000);
  }

  // Apply the RF configuration
  radio.setPALevel(RF24_PA_MAX);
  radio.setDataRate(RF24_1MBPS);
  radio.setCRCLength(RF24_CRC_16);
  radio.setPayloadSize(PAYLOAD_SIZE);
  radio.setAutoAck(false);

  radio.openWritingPipe(TX_ADDRESS);
  radio.openReadingPipe(1, RX_ADDRESS);

  // Share our clock with the receiver
  timeSync();
}

void loop() {
  updateChannel();

  // Skip transmission near slot boundaries to tolerate clock drift
  int64_t inSlot = nowUs() % HOP_INTERVAL_US;
  if (inSlot < GUARD_US || inSlot > HOP_INTERVAL_US - GUARD_US) return;

  // Building payload
  memset(&packet, 0, sizeof(packet));
  packet.type = PKT_DATA;
  packet.channel = currentChannel;
  packet.timeUs = nowUs();
  snprintf(packet.text, sizeof(packet.text), "hello%lu", counter++);

  // Encrypting and sending payload
  sendPacket();

  // Printing raw payload and encrypted payload
  Serial.printf("Sent on ch %u: %s | Encrypted (hex): ", currentChannel, packet.text);
  for (uint8_t i = 0; i < PAYLOAD_SIZE; i++) {
    if (encryptedBuffer[i] < 0x10) Serial.print('0');
    Serial.print(encryptedBuffer[i], HEX);
    Serial.print(' ');
  }
  Serial.println();

  delay(1000);   // Send every 10 ms
}
