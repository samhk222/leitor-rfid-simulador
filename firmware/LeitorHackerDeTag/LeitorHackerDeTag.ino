#define MFRC522_SPICLOCK 1000000   // SPI a 1 MHz (precisa vir ANTES do include)
#include <SPI.h>
#include <MFRC522.h>
#include <Preferences.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#if defined(CONFIG_BLUEDROID_ENABLED)
#include <BLE2902.h>   // no NimBLE (padrao do S3) o descritor 2902 e criado sozinho
#endif

// ---------- Pinos (ajuste se necessario) ----------
#define SCK_PIN   4
#define MISO_PIN  5
#define MOSI_PIN  6
#define SS_PIN    7
#define RST_PIN   8

// Bloco de dados usado para ler/gravar (NUNCA use bloco 0 nem blocos trailer: 3, 7, 11...)
#define BLOCO_DADOS 4

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;
Preferences prefs;

enum Modo { NENHUM, LEITURA, SALVAR, GRAVAR };
Modo modo = NENHUM;

// ---------- Bluetooth (BLE, Nordic UART Service) ----------
// O ESP32-S3 so tem BLE (sem Bluetooth classico/SPP), entao a "serial sem fio" usa o NUS.
#define BLE_NOME        "LeitorRFID"
#define NUS_SERVICE_UUID "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define NUS_RX_UUID      "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"  // navegador -> ESP (write)
#define NUS_TX_UUID      "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"  // ESP -> navegador (notify)

BLEServer *bleServer = nullptr;
BLECharacteristic *bleTx = nullptr;
volatile bool bleConectado = false;
bool bleConectadoAntes = false;
QueueHandle_t filaBle;          // comandos recebidos via BLE (callback roda em outra task)

uint8_t bleBuf[20];             // 20 bytes = payload do MTU padrao (23)
size_t bleLen = 0;

void bleFlush() {
  if (bleLen == 0) return;
  if (bleConectado) {
    bleTx->setValue(bleBuf, bleLen);
    bleTx->notify();
    delay(5);                   // da folga para a pilha BLE nao descartar notificacoes
  }
  bleLen = 0;
}

// Tudo que e impresso vai para a USB e, se houver conexao, para o BLE
class SaidaDupla : public Print {
 public:
  size_t write(uint8_t c) override {
    Serial.write(c);
    if (bleConectado) {
      bleBuf[bleLen++] = c;
      if (c == '\n' || bleLen >= sizeof(bleBuf)) bleFlush();
    }
    return 1;
  }
};
SaidaDupla Out;

class BleServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer *) override { bleConectado = true; }
  void onDisconnect(BLEServer *) override { bleConectado = false; }
};

class BleRxCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *c) override {
    String v = c->getValue();
    for (size_t i = 0; i < v.length(); i++) {
      char ch = v[i];
      xQueueSend(filaBle, &ch, 0);
    }
  }
};

void iniciarBle() {
  filaBle = xQueueCreate(64, sizeof(char));
  BLEDevice::init(BLE_NOME);
  bleServer = BLEDevice::createServer();
  bleServer->setCallbacks(new BleServerCallbacks());

  BLEService *svc = bleServer->createService(NUS_SERVICE_UUID);
  bleTx = svc->createCharacteristic(NUS_TX_UUID, BLECharacteristic::PROPERTY_NOTIFY);
#if defined(CONFIG_BLUEDROID_ENABLED)
  bleTx->addDescriptor(new BLE2902());
#endif
  BLECharacteristic *rx = svc->createCharacteristic(
      NUS_RX_UUID, BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR);
  rx->setCallbacks(new BleRxCallbacks());
  svc->start();

  BLEAdvertising *adv = BLEDevice::getAdvertising();
  adv->addServiceUUID(NUS_SERVICE_UUID);
  adv->start();
}

void mostrarMenu();

void manterBle() {
  bleFlush();
  if (!bleConectado && bleConectadoAntes) {   // desconectou: volta a anunciar
    delay(500);
    bleServer->startAdvertising();
    bleConectadoAntes = false;
  }
  if (bleConectado && !bleConectadoAntes) {   // acabou de conectar: mostra o menu
    bleConectadoAntes = true;
    delay(500);                               // espera o navegador ativar as notificacoes
    Out.println(F("Conectado via Bluetooth."));
    mostrarMenu();
  }
}

// ---------- Utilidades ----------
void printHex(const byte *buf, byte len) {
  for (byte i = 0; i < len; i++) {
    if (buf[i] < 0x10) Out.print('0');
    Out.print(buf[i], HEX);
    Out.print(' ');
  }
}

void mostrarMenu() {
  Out.println();
  Out.println(F("===== MENU ====="));
  Out.println(F("1 - Modo LEITURA (mostra UID e dados da tag)"));
  Out.println(F("2 - Modo SALVAR (le a tag e guarda na memoria do ESP)"));
  Out.println(F("3 - Modo GRAVAR (grava UID + dados salvos em outra tag)"));
  Out.println(F("4 - Ver valor salvo na memoria"));
  Out.println(F("5 - Apagar valor salvo"));
  Out.println(F("m - Mostrar menu"));
  Out.println(F("================"));
}

void encerrarTag() {
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}

bool autenticar(byte bloco) {
  MFRC522::StatusCode st = mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A, bloco, &key, &(mfrc522.uid));
  if (st != MFRC522::STATUS_OK) {
    Out.print(F("Falha na autenticacao: "));
    Out.println(mfrc522.GetStatusCodeName(st));
    return false;
  }
  return true;
}

bool lerBloco(byte bloco, byte *saida16) {
  if (!autenticar(bloco)) return false;
  byte buffer[18];
  byte tam = sizeof(buffer);
  MFRC522::StatusCode st = mfrc522.MIFARE_Read(bloco, buffer, &tam);
  if (st != MFRC522::STATUS_OK) {
    Out.print(F("Falha na leitura: "));
    Out.println(mfrc522.GetStatusCodeName(st));
    return false;
  }
  memcpy(saida16, buffer, 16);
  return true;
}

bool gravarBloco(byte bloco, const byte *dados16) {
  if (!autenticar(bloco)) return false;
  MFRC522::StatusCode st = mfrc522.MIFARE_Write(bloco, (byte *)dados16, 16);
  if (st != MFRC522::STATUS_OK) {
    Out.print(F("Falha na gravacao: "));
    Out.println(mfrc522.GetStatusCodeName(st));
    return false;
  }
  return true;
}

// ---------- Gravacao de UID (magic cards) ----------
byte UNLOCK1_CMD[] = {0x40};
byte UNLOCK2_CMD[] = {0x43};

bool magicGen1aAbrirBackdoor() {
  byte validBits = 7;
  byte resp[1];
  byte respLen = 1;

  MFRC522::StatusCode st = mfrc522.PCD_TransceiveData(
      UNLOCK1_CMD, 1, resp, &respLen, &validBits, 0, false);
  if (st != MFRC522::STATUS_OK || respLen != 1 || resp[0] != 0x0A) return false;

  st = mfrc522.PCD_TransceiveData(
      UNLOCK2_CMD, 1, resp, &respLen, &validBits, 0, false);
  if (st != MFRC522::STATUS_OK || respLen != 1 || resp[0] != 0x0A) return false;

  return true;
}

bool gravarUidGen1a(const byte *uidNovo, byte uidLen) {
  if (uidLen != 4) {
    Out.println(F("Gen1a so suporta UID de 4 bytes."));
    return false;
  }
  if (!magicGen1aAbrirBackdoor()) {
    Out.println(F("Nao foi possivel abrir o backdoor (tag nao e Gen1a?)."));
    return false;
  }

  byte bloco0[16];
  memcpy(bloco0, uidNovo, 4);
  byte bcc = uidNovo[0] ^ uidNovo[1] ^ uidNovo[2] ^ uidNovo[3];
  bloco0[4] = bcc;
  bloco0[5] = 0x08;  // SAK tipico de MIFARE 1K
  bloco0[6] = 0x04;
  bloco0[7] = 0x00;
  for (byte i = 8; i < 16; i++) bloco0[i] = 0x00;

  MFRC522::StatusCode st = mfrc522.MIFARE_Write(0, bloco0, 16);
  if (st != MFRC522::STATUS_OK) {
    Out.print(F("Falha ao gravar bloco 0 (Gen1a): "));
    Out.println(mfrc522.GetStatusCodeName(st));
    return false;
  }
  return true;
}

bool gravarUidGen2(const byte *uidNovo, byte uidLen) {
  if (!autenticar(0)) return false;

  byte bloco0[16];
  memcpy(bloco0, uidNovo, uidLen);
  if (uidLen == 4) {
    byte bcc = uidNovo[0] ^ uidNovo[1] ^ uidNovo[2] ^ uidNovo[3];
    bloco0[4] = bcc;
    bloco0[5] = 0x08;
    bloco0[6] = 0x04;
    bloco0[7] = 0x00;
    for (byte i = 8; i < 16; i++) bloco0[i] = 0x00;
  }

  MFRC522::StatusCode st = mfrc522.MIFARE_Write(0, bloco0, 16);
  if (st != MFRC522::STATUS_OK) {
    Out.print(F("Falha ao gravar bloco 0 (Gen2): "));
    Out.println(mfrc522.GetStatusCodeName(st));
    return false;
  }
  return true;
}

bool gravarUid(const byte *uidNovo, byte uidLen) {
  Out.println(F("Tentando como Gen2/CUID..."));
  if (gravarUidGen2(uidNovo, uidLen)) return true;

  Out.println(F("Tentando como Gen1a (backdoor)..."));
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  if (gravarUidGen1a(uidNovo, uidLen)) return true;

  Out.println(F("Nao foi possivel gravar o UID. A tag de destino e magic card?"));
  return false;
}

// ---------- Memoria (Preferences) ----------
void mostrarSalvo() {
  prefs.begin("rfid", true);
  bool tem = prefs.getBool("tem", false);
  if (!tem) {
    Out.println(F("Nenhum valor salvo na memoria."));
  } else {
    byte uid[10], dados[16];
    byte uidLen = prefs.getUChar("uidLen", 0);
    prefs.getBytes("uid", uid, uidLen);
    prefs.getBytes("dados", dados, 16);
    Out.print(F("UID salvo : ")); printHex(uid, uidLen); Out.println();
    Out.print(F("Dados salvos (bloco ")); Out.print(BLOCO_DADOS);
    Out.print(F("): ")); printHex(dados, 16); Out.println();
  }
  prefs.end();
}

// ---------- Serial ----------
void processarComando(char c) {
    if (c == '\n' || c == '\r' || c == ' ') return;

    switch (c) {
      case '1':
        modo = LEITURA;
        Out.println(F("\n[MODO LEITURA] Aproxime uma tag... (envie outro comando para sair)"));
        break;
      case '2':
        modo = SALVAR;
        Out.println(F("\n[MODO SALVAR] Aproxime a tag que sera salva na memoria..."));
        break;
      case '3':
        prefs.begin("rfid", true);
        {
          bool tem = prefs.getBool("tem", false);
          prefs.end();
          if (!tem) {
            Out.println(F("\nNao ha valor salvo! Use o modo 2 primeiro."));
            modo = NENHUM;
            break;
          }
        }
        modo = GRAVAR;
        Out.println(F("\n[MODO GRAVAR] Aproxime a tag de DESTINO (deve ser magic card para copiar o UID)..."));
        break;
      case '4':
        modo = NENHUM;
        Out.println();
        mostrarSalvo();
        break;
      case '5':
        modo = NENHUM;
        prefs.begin("rfid", false);
        prefs.clear();
        prefs.end();
        Out.println(F("\nMemoria apagada."));
        break;
      case 'm':
      case 'M':
        modo = NENHUM;
        mostrarMenu();
        break;
      default:
        Out.println(F("\nComando invalido. Envie 'm' para ver o menu."));
        break;
    }
}

// Comandos chegam pela USB (Serial) ou pelo Bluetooth (fila preenchida no callback BLE)
void tratarSerial() {
  while (Serial.available()) processarComando(Serial.read());
  char c;
  while (xQueueReceive(filaBle, &c, 0) == pdTRUE) processarComando(c);
}

// ---------- Setup / Loop ----------
void setup() {
  Serial.begin(115200);
  unsigned long t = millis();
  while (!Serial && millis() - t < 3000);

  SPI.begin(SCK_PIN, MISO_PIN, MOSI_PIN, SS_PIN);
  mfrc522.PCD_Init();
  delay(4);

  mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_18dB);  // ajustado conforme teste no seu modulo

  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;  // chave padrao

  iniciarBle();

  Out.println(F("RFID RC522 + ESP32-S3"));
  Out.print(F("Firmware Version: 0x"));
  Out.println(mfrc522.PCD_ReadRegister(MFRC522::VersionReg), HEX);
  Out.print(F("Bluetooth: anunciando como \""));
  Out.print(F(BLE_NOME));
  Out.println(F("\""));
  mostrarMenu();
}

void loop() {
  manterBle();
  tratarSerial();

  if (modo == NENHUM) return;
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) return;

  byte uidLen = mfrc522.uid.size;
  byte dados[16];

  switch (modo) {
    case LEITURA:
      Out.print(F("UID: ")); printHex(mfrc522.uid.uidByte, uidLen); Out.println();
      Out.print(F("Tipo: "));
      Out.println(mfrc522.PICC_GetTypeName(mfrc522.PICC_GetType(mfrc522.uid.sak)));
      if (lerBloco(BLOCO_DADOS, dados)) {
        Out.print(F("Bloco ")); Out.print(BLOCO_DADOS); Out.print(F(": "));
        printHex(dados, 16); Out.println();
      }
      encerrarTag();
      delay(1500);
      break;

    case SALVAR:
      if (lerBloco(BLOCO_DADOS, dados)) {
        prefs.begin("rfid", false);
        prefs.putUChar("uidLen", uidLen);
        prefs.putBytes("uid", mfrc522.uid.uidByte, uidLen);
        prefs.putBytes("dados", dados, 16);
        prefs.putBool("tem", true);
        prefs.end();
        Out.println(F("Valor salvo na memoria do ESP!"));
        Out.print(F("UID: ")); printHex(mfrc522.uid.uidByte, uidLen); Out.println();
        Out.print(F("Dados: ")); printHex(dados, 16); Out.println();
      }
      encerrarTag();
      modo = NENHUM;
      mostrarMenu();
      break;

    case GRAVAR: {
      prefs.begin("rfid", true);
      byte uidSalvo[10];
      byte uidSalvoLen = prefs.getUChar("uidLen", 0);
      prefs.getBytes("uid", uidSalvo, uidSalvoLen);
      prefs.getBytes("dados", dados, 16);
      prefs.end();

      bool uidOk = gravarUid(uidSalvo, uidSalvoLen);
      if (uidOk) {
        Out.println(F("UID gravado! Re-selecionando a tag..."));
        mfrc522.PICC_HaltA();
        mfrc522.PCD_StopCrypto1();
        delay(100);
        if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
          Out.println(F("Nao foi possivel reselecionar a tag apos gravar o UID."));
          modo = NENHUM;
          mostrarMenu();
          break;
        }
      }

      if (gravarBloco(BLOCO_DADOS, dados)) {
        byte conferencia[16];
        if (lerBloco(BLOCO_DADOS, conferencia) && memcmp(dados, conferencia, 16) == 0) {
          Out.println(F("Gravacao de dados concluida e verificada!"));
        } else {
          Out.println(F("Dados gravados, mas verificacao falhou."));
        }
      }
      encerrarTag();
      modo = NENHUM;
      mostrarMenu();
      break;
    }

    default:
      break;
  }
}