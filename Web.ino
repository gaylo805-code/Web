/*
 * Web.ino
 * Sketch mặc định cho ESP32 - build qua Web IDE
 * Sửa file này (hoặc upload file .ino khác cùng tên) để thay đổi chương trình chạy trên ESP32.
 */

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("✅ ESP32 đã khởi động - Web IDE Build");
}

void loop() {
  Serial.println("💓 Heartbeat...");
  delay(2000);
}
