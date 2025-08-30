/*
 * Telemetry
 * Developed by AQL Intelligence.
 * https://github.com/azrael-sec/telemetry
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * compiler: g++ src/main.cpp -std=c++17 -lcurl -o app
 * or run (linux): rm -rf build && mkdir build && cd build && cmake .. && make && ./telemetry
 */

#include <cstdio>
#include <cstdlib>
#include <string>
#include <map>
#include <sstream>
#include <curl/curl.h>
#include <ctime>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#include <iphlpapi.h>
#include <lm.h>
#include <sysinfoapi.h>
#include <intrin.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#else
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/types.h>
#include <pwd.h>
#endif

#define ENDPOINT "http://localhost:8080/v1/ingest" // Endpoint -> save metadata

// timestamp ISO8601 UTC
static std::string iso8601_utc() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ", 
    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  return std::string(buf);
}

static std::string json_escape(const std::string& s) {
  std::ostringstream o; o<<'"';
  for(char c: s){
    switch(c){
      case '"': o<<"\\\""; break;
      case '\\': o<<"\\\\"; break;
      case '\n': o<<"\\n"; break;
      default: o<<c; break;
    }
  } o<<'"'; return o.str();
}

static std::string json_obj(const std::map<std::string,std::string>& kv){
  std::ostringstream o; o<<"{"; bool first=true;
  for(auto &p: kv){ if(!first) o<<","; first=false; o<<json_escape(p.first)<<":"<<json_escape(p.second);} o<<"}"; return o.str();
}

// HTTP POST JSON
static bool postJson(const std::string& url, const std::string& json){
  CURL* curl = curl_easy_init(); if(!curl) return false;
  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)json.size());
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  long code=0; CURLcode rc = curl_easy_perform(curl);
  if(rc==CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  curl_slist_free_all(headers); curl_easy_cleanup(curl);
  return rc==CURLE_OK && code>=200 && code<300;
}

// Collect system metadata
#if defined(_WIN32)
static std::string get_windows_version() {
  OSVERSIONINFOEX osvi;
  ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
  osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
  if (GetVersionEx((OSVERSIONINFO*)&osvi)) {
    return std::to_string(osvi.dwMajorVersion) + "." + std::to_string(osvi.dwMinorVersion) + "." + std::to_string(osvi.dwBuildNumber);
  } return "unknown";
}

static std::string get_cpu_info() {
  int CPUInfo[4] = {-1};
  char CPUBrandString[0x40] = {0};
  __cpuid(CPUInfo, 0x80000000);
  unsigned int nExIds = CPUInfo[0];
  for (unsigned int i = 0x80000000; i <= nExIds; ++i) {
    __cpuid(CPUInfo, i);
    if (i == 0x80000002) memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
    else if (i == 0x80000003) memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
    else if (i == 0x80000004) memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
  } return std::string(CPUBrandString);
}

static std::string get_memory_info() {
  MEMORYSTATUSEX memInfo;
  memInfo.dwLength = sizeof(MEMORYSTATUSEX);
  GlobalMemoryStatusEx(&memInfo);
  return std::to_string(memInfo.ullTotalPhys / (1024 * 1024)) + " MB";
}

static std::string get_network_info() {
  PIP_ADAPTER_INFO pAdapterInfo;
  PIP_ADAPTER_INFO pAdapter = NULL;
  DWORD dwRetVal = 0;
  ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
  pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
  if (pAdapterInfo == NULL) return "unknown";
  if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
    free(pAdapterInfo);
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    if (pAdapterInfo == NULL) return "unknown";
  }
  std::string result;
  if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
    pAdapter = pAdapterInfo;
    while (pAdapter) {
      result += pAdapter->Description;
      result += " (" + std::string(pAdapter->IpAddressList.IpAddress.String) + "); ";
      pAdapter = pAdapter->Next;
    }
  }
  free(pAdapterInfo);
  return result.empty() ? "none" : result;
}
#else

static std::string get_linux_version() {
  struct utsname buf;
  if (uname(&buf) == 0) { return std::string(buf.sysname) + " " + buf.release + " " + buf.machine; }
  return "unknown";
}

static std::string get_cpu_info() {
  FILE* cpuinfo = fopen("/proc/cpuinfo", "r");
  if (!cpuinfo) return "unknown";
  char line[256];
  while (fgets(line, sizeof(line), cpuinfo)) {
    if (strncmp(line, "model name", 10) == 0) {
      char* colon = strchr(line, ':');
      if (colon) {
        fclose(cpuinfo);
        colon++;
        while (*colon == ' ' || *colon == '\t') colon++;
        char* newline = strchr(colon, '\n');
        if (newline) *newline = '\0';
        return std::string(colon);
      }
    }
  }
  fclose(cpuinfo);
  return "unknown";
}

static std::string get_memory_info() {
  struct sysinfo info;
  if (sysinfo(&info) == 0) { return std::to_string(info.totalram * info.mem_unit / (1024 * 1024)) + " MB"; }
  return "unknown";
}

static std::string get_network_info() {
  struct ifaddrs *ifaddr, *ifa;
  std::string result;
  if (getifaddrs(&ifaddr) == -1) return "unknown";
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) continue;
    int family = ifa->ifa_addr->sa_family;
    if (family == AF_INET) { // IPv4
      char host[NI_MAXHOST];
      int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, 
        NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
      if (s == 0) { result += std::string(ifa->ifa_name) + " (" + host + "); "; }
    }
  }
  freeifaddrs(ifaddr);
  return result.empty() ? "none" : result;
}
#endif

static std::string get_username() {
#if defined(_WIN32)
  char username[256];
  DWORD size = sizeof(username);
  if (GetUserNameA(username, &size)) {
    return std::string(username);
  }
#else
  struct passwd *pw = getpwuid(getuid());
  if (pw) return std::string(pw->pw_name);
#endif
  return "unknown";
}

static std::string get_hostname() {
  char hostname[256];
#if defined(_WIN32)
  DWORD size = sizeof(hostname);
  if (GetComputerNameA(hostname, &size)) {
    return std::string(hostname);
  }
#else
  if (gethostname(hostname, sizeof(hostname)) == 0) { return std::string(hostname); }
#endif
  return "unknown";
}

int main(){
  // Collect metadata
  std::map<std::string,std::string> metadata;
  metadata["ts"] = iso8601_utc();
  metadata["event"] = "system_metadata";
  metadata["user"] = get_username();
  metadata["hostname"] = get_hostname();
    
#if defined(_WIN32)
  metadata["os"] = "Windows";
  metadata["os_version"] = get_windows_version();
#else
  metadata["os"] = "Linux";
  metadata["os_version"] = get_linux_version();
#endif
  metadata["cpu"] = get_cpu_info();
  metadata["memory"] = get_memory_info();
  metadata["network"] = get_network_info();
  metadata["architecture"] = 
#if defined(_WIN64) || defined(__x86_64__) || defined(__ppc64__)
  "64-bit";
#else
  "32-bit";
#endif
    
#if !defined(_WIN32)
  struct sysinfo info;
  if (sysinfo(&info) == 0) {
    std::time_t boot_time = std::time(nullptr) - info.uptime;
    std::tm* tm = std::gmtime(&boot_time);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
    metadata["boot_time"] = buf;
  }
#endif
  std::string payload = json_obj(metadata);
  bool ok = postJson(ENDPOINT, payload);
  if(ok) { std::printf("[OK] Successfully!\n\n"); } 
  else { std::printf("[ERROR] Failed to send system metadata.\n"); }
  return 0;
}
