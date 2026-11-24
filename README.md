# Leitor RFID: simulador

Simulador web do sketch LeitorHackerDeTag (ESP32-S3 + RC522): Serial Monitor com o mesmo menu e tags MIFARE Classic 1K virtuais (normal, Magic Gen1a, Magic Gen2/CUID).

**▶ Abrir o app:** [samhk222.github.io/leitor-rfid-simulador](https://samhk222.github.io/leitor-rfid-simulador/)

## Conectar à placa real

- **Bluetooth (BLE):** o sketch anuncia `LeitorRFID` com o Nordic UART Service. Clique em "Conectar via Bluetooth".
- **USB:** clique em "Conectar via USB" e escolha a porta do ESP32 (115200 baud).

Requer Chrome ou Edge (Web Bluetooth / Web Serial). Safari e iOS não suportam.

## Firmware

O sketch do ESP32-S3 + RC522 está em [`firmware/LeitorHackerDeTag/LeitorHackerDeTag.ino`](firmware/LeitorHackerDeTag/LeitorHackerDeTag.ino). Abra essa pasta no Arduino IDE (core esp32 3.x, placa ESP32S3, lib MFRC522).
