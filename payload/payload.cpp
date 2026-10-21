#include <windows.h>

#include <cstdio>

namespace {

volatile bool g_running = false;

}  // namespace

extern "C" __declspec(dllexport) void payload_stop() {
  g_running = false;
}

extern "C" __declspec(dllexport) int payload_run() {
  g_running = true;
  std::printf("payload_run: sealed DLL started\n");
  while (g_running) {
    Sleep(250);
  }
  std::printf("payload_run: stopped\n");
  return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(module);
  }
  return TRUE;
}
