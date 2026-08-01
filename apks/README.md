# APK samples

Drop `.apk` files here (Docker mounts this at `/app/apks`).

## Static analysis

```text
apk_analyze(action="download", url="https://example.com/app.apk")
apk_analyze(action="report", apk="/app/apks/app.apk")
```

## Dynamic (host emulator via ADB)

1. On the **host**, start ADB listening on all interfaces and boot an AVD:

```bash
adb kill-server
adb -a nodaemon server start
# then start Android Studio Virtual Device / Genymotion / etc.
adb devices
```

2. From Sleuth chat:

```text
apk_device(action="devices")
apk_device(action="install", apk="/app/apks/app.apk")
apk_device(action="launch", package="com.example.app")
apk_device(action="logcat", package="com.example.app", lines=200)
apk_device(action="screenshot")
# or one-shot:
apk_device(action="run_pipeline", apk="/app/apks/app.apk")
```

Screenshots and pulls land in `apks/device_out/`.

Use an **isolated analysis emulator** only — do not install untrusted samples on a personal phone.
