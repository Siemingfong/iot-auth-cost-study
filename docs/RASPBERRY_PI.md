# 樹莓派量測操作說明

這份說明給負責在樹莓派上量測的共同作者。兩台都要測：**Raspberry Pi Zero 2 W** 和 **Raspberry Pi 4（2 GB）**，每台的步驟相同。

量測內容是論文中「裝置端簽章」和「批次驗證」的執行時間，結果會寫進論文的跨平台比較表。

---

## 1. 燒錄系統（每台一次）

1. 在電腦上安裝 [Raspberry Pi Imager](https://www.raspberrypi.com/software/)。
2. 選擇裝置型號，作業系統選 **Raspberry Pi OS Lite (64-bit)**。
   - ⚠️ **一定要選 64-bit**。32 位元版本無法安裝量測需要的密碼學套件。
3. 在進階設定中：設定使用者名稱與密碼、填入 Wi-Fi、**啟用 SSH**。
4. 燒錄完成後插入 microSD 卡，接上**套件附的原廠電源**開機。

## 2. 登入並安裝工具

用 SSH 從電腦登入（或接螢幕和鍵盤；Zero 2 W 需要套件附的 Mini HDMI 轉接頭和 USB OTG 線）：

```bash
ssh <使用者名稱>@<樹莓派的 IP 或主機名稱>.local
sudo apt update
sudo apt install -y git python3-venv
git clone https://github.com/Siemingfong/iot-auth-cost-study.git
cd iot-auth-cost-study/offchain
```

確認是 64 位元系統，下面指令應該顯示 `aarch64`：

```bash
uname -m
```

## 3. 先跑一次測試（約幾分鐘）

```bash
QUICK=1 bash run_device_bench.sh
```

最後出現 `Done.` 就代表環境沒問題。**測試的結果不用回傳**。

## 4. 正式量測

正式量測前請：
- **重新開機**（`sudo reboot`），重新登入後不要執行其他程式。
- 使用**套件附的原廠電源**（電壓不足會讓處理器降頻，數據就不準了）。
- 放在通風的地方，不要包在密閉空間裡。

量測時間較長，Zero 2 W 尤其需要耐心。為了避免 SSH 斷線中斷量測，請用下面的方式在背景執行：

```bash
cd ~/iot-auth-cost-study/offchain
nohup bash run_device_bench.sh > run.log 2>&1 &
tail -f run.log        # 觀察進度；按 Ctrl+C 只會停止觀察，不會中斷量測
```

## 5. 確認結果

`run.log` 最後應該出現：

```
Done. Send this file back:  offchain/results-device-....tar.gz
Throttling flags after the run: 0x0 (0x0 means none)
```

- 如果是 **`0x0`**：數據可用。
- 如果**不是 `0x0`**：表示量測途中發生降頻或電壓不足，數據不可用。請檢查電源和散熱、重新開機後再跑一次。

## 6. 回傳結果

在**自己的電腦**上執行，把結果檔複製下來：

```bash
scp <使用者名稱>@<樹莓派位址>:~/iot-auth-cost-study/offchain/results-device-*.tar.gz .
```

把 `.tar.gz` 檔案寄給謝銘峰（mingfong@cycu.edu.tw），並註明是哪一台。兩台都完成後就結束了。

有任何錯誤訊息，直接截圖或複製全文回報即可。
